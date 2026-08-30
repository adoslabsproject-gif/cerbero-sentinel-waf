//! ShardedLru — LRU concorrente true-O(1), primitivo CONDIVISO del WAF.
//!
//! Sostituisce la batch-eviction ammortizzata (collect → sort O(n log n) → drop
//! ~10%) con una vera LRU: eviction e promote sono O(1), e il worst-case NON
//! scala col volume dell'attacco (classe DD1 — "il lavoro del WAF non deve
//! scalare con l'attacco"). La mappa è cappata e self-bounding (anti-OOM,
//! SESSION1/EL1).
//!
//! Concorrenza: `lru::LruCache` NON è thread-safe → lo wrappiamo in N shard
//! `parking_lot::Mutex<LruCache>` (key-hash → shard). Così niente lock GLOBALE
//! (che serializzerebbe il hot-path del WAF): la contention è ~1/N e ogni
//! sezione critica è O(1) (poche decine di ns). `parking_lot::Mutex` è
//! non-poisoning by design (un panic in una sezione critica non avvelena il
//! lock — coerente col fix lock-poisoning C4).

use std::borrow::Borrow;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};
use std::num::NonZeroUsize;

use lru::LruCache;
use parking_lot::Mutex;

/// Numero di shard di default (potenza di 2 non richiesta: usiamo `%`).
pub const DEFAULT_SHARDS: usize = 16;

/// LRU concorrente sharded. `total_cap` è distribuito equamente sugli shard;
/// la capacità effettiva è `num_shards * (total_cap / num_shards)` (≤ total_cap,
/// per arrotondamento), sempre ≥ num_shards.
///
/// Hashing **seed-randomizzato per-istanza** (LR1): sia la selezione dello shard
/// sia l'hashmap interna di ogni `LruCache` usano `RandomState` (seed casuale a
/// ogni costruzione). Con un seed FISSO (`DefaultHasher::new()`, SipHash keys 0,0)
/// la mappatura key→shard sarebbe predicibile e un attaccante che conosce le proprie
/// key potrebbe concentrare il flood su UN solo shard (1/N della capacità) →
/// thrashing mirato che sfratta più in fretta le vittime legittime di quello shard
/// (shard-targeting, parente di HashDoS). Col seed random l'avversario non può
/// prevedere quale shard colpiranno le sue key.
pub struct ShardedLru<K: Hash + Eq, V> {
    shards: Vec<Mutex<LruCache<K, V, RandomState>>>,
    /// `BuildHasher` con seed casuale per-istanza per la SELEZIONE dello shard (LR1).
    shard_hasher: RandomState,
}

impl<K: Hash + Eq, V> ShardedLru<K, V> {
    /// Crea con capacità totale `total_cap` su `DEFAULT_SHARDS` shard.
    pub fn new(total_cap: usize) -> Self {
        Self::with_shards(total_cap, DEFAULT_SHARDS)
    }

    /// Crea con `num_shards` shard (≥1) e capacità totale `total_cap`.
    pub fn with_shards(total_cap: usize, num_shards: usize) -> Self {
        let num_shards = num_shards.max(1);
        let per_shard = NonZeroUsize::new((total_cap / num_shards).max(1))
            .expect("per_shard ≥ 1 garantito da .max(1)");
        // Ogni shard ha un `RandomState` PROPRIO (seed casuale) → anche l'hashing
        // INTERNO della LruCache è imprevedibile (no collision-flooding intra-shard).
        let shards = (0..num_shards)
            .map(|_| Mutex::new(LruCache::with_hasher(per_shard, RandomState::new())))
            .collect();
        Self {
            shards,
            shard_hasher: RandomState::new(),
        }
    }

    /// Indice di shard per una key borrowed (`&Q`), via il `shard_hasher`
    /// seed-randomizzato per-istanza (LR1). `K: Borrow<Q>` garantisce che l'hash di
    /// `Q` coincida con quello di `K` (es. str vs String) → stesso shard.
    fn shard_idx<Q: Hash + ?Sized>(&self, key: &Q) -> usize {
        (self.shard_hasher.hash_one(key) as usize) % self.shards.len()
    }

    /// Shard per una key borrowed (`&Q`). Lookup senza allocare la key owned sull'hot-path.
    fn shard_q<Q: Hash + ?Sized>(&self, key: &Q) -> &Mutex<LruCache<K, V, RandomState>> {
        &self.shards[self.shard_idx(key)]
    }

    fn shard(&self, key: &K) -> &Mutex<LruCache<K, V, RandomState>> {
        self.shard_q(key)
    }

    /// Numero di entry totali (somma per-shard).
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| s.lock().is_empty())
    }

    /// Capacità totale effettiva (somma delle capacità per-shard).
    pub fn capacity(&self) -> usize {
        self.shards.iter().map(|s| s.lock().cap().get()).sum()
    }
}

impl<K: Hash + Eq + Clone, V> ShardedLru<K, V> {
    /// Accede in mutazione (promote recency O(1)). `f` riceve `Some` se presente.
    /// Lookup borrowed (`&Q`) → niente alloc della key owned sull'hot-path.
    pub fn with_get_mut<Q, R>(&self, key: &Q, f: impl FnOnce(Option<&mut V>) -> R) -> R
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut cache = self.shard_q(key).lock();
        f(cache.get_mut(key))
    }

    /// Legge SENZA promuovere la recency (per letture che non devono "toccare"
    /// la sessione, es. uno scoring che non deve tenerla in vita).
    pub fn with_peek<Q, R>(&self, key: &Q, f: impl FnOnce(Option<&V>) -> R) -> R
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let cache = self.shard_q(key).lock();
        f(cache.peek(key))
    }

    /// Upsert atomico: aggiorna se presente, altrimenti inserisce `default()`.
    /// Se lo shard è al cap, l'inserimento evicta la LRU in O(1).
    pub fn upsert(&self, key: K, default: impl FnOnce() -> V, update: impl FnOnce(&mut V)) {
        let mut cache = self.shard(&key).lock();
        if let Some(v) = cache.get_mut(&key) {
            update(v);
        } else {
            cache.put(key, default());
        }
    }

    /// Inserisce/rimpiazza (promote). Ritorna l'eventuale entry evicted (LRU).
    pub fn put(&self, key: K, value: V) -> Option<(K, V)> {
        self.shard(&key).lock().push(key, value)
    }

    /// Get-or-create + muta + ritorna un risultato, atomically sotto lock. Se la
    /// key è assente inserisce `default()` (evict LRU O(1) se lo shard è pieno),
    /// poi applica `f(&mut V)` (promote recency O(1)). È il pattern dei rate
    /// limiter (get-or-create per-IP + avanza finestra + decidi allow/deny).
    pub fn with_entry_mut<R>(
        &self,
        key: K,
        default: impl FnOnce() -> V,
        f: impl FnOnce(&mut V) -> R,
    ) -> R {
        let mut cache = self.shard(&key).lock();
        let v = cache.get_or_insert_mut(key, default);
        f(v)
    }

    /// Rimuove e ritorna l'entry.
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.shard_q(key).lock().pop(key)
    }

    /// Rimuove e ritorna l'entry SE `pred(&V)` è true — ATOMICO sotto il lock dello shard
    /// (equivalente a `DashMap::remove_if` sul valore). Per il pattern expire-then-read
    /// senza race fra il check e la rimozione.
    pub fn remove_if<Q>(&self, key: &Q, pred: impl FnOnce(&V) -> bool) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut cache = self.shard_q(key).lock();
        let hit = cache.peek(key).map(pred).unwrap_or(false);
        if hit {
            cache.pop(key)
        } else {
            None
        }
    }

    /// Svuota tutti gli shard.
    pub fn clear(&self) {
        for shard in &self.shards {
            shard.lock().clear();
        }
    }

    /// True se la key è presente (NO promote).
    pub fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.shard_q(key).lock().contains(key)
    }

    /// Cleanup periodico: tiene solo le entry per cui `keep` è true (le altre
    /// rimosse). `keep` riceve `&mut V` → può anche MUTARE l'entry prima di
    /// decidere (es. prune di finestre temporali interne). O(n) ma chiamato
    /// fuori dal hot-path (janitor periodico).
    pub fn retain(&self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        for shard in &self.shards {
            let mut cache = shard.lock();
            let drop_keys: Vec<K> = cache
                .iter_mut()
                .filter_map(|(k, v)| if keep(k, v) { None } else { Some(k.clone()) })
                .collect();
            for k in drop_keys {
                cache.pop(&k);
            }
        }
    }

    /// Applica `f` in mutazione a OGNI entry (per reset/manutenzione periodica
    /// su tutte le entry, es. azzerare un contatore a finestra). O(n), janitor.
    pub fn for_each_mut(&self, mut f: impl FnMut(&K, &mut V)) {
        for shard in &self.shards {
            let mut cache = shard.lock();
            for (k, v) in cache.iter_mut() {
                f(k, v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_distributed_across_shards() {
        let lru: ShardedLru<u64, u64> = ShardedLru::with_shards(160, 16);
        assert_eq!(lru.capacity(), 160); // 16 * (160/16)=10
        // total non divisibile → capacità ≤ total
        let lru2: ShardedLru<u64, u64> = ShardedLru::with_shards(100, 16);
        assert_eq!(lru2.capacity(), 96); // 16 * (100/16=6)
        assert!(lru2.capacity() <= 100);
    }

    #[test]
    fn per_shard_cap_at_least_one() {
        // total < num_shards → ogni shard ha comunque cap 1 (no panic NonZero).
        let lru: ShardedLru<u64, u64> = ShardedLru::with_shards(4, 16);
        assert_eq!(lru.capacity(), 16); // 16 * max(1, 4/16=0)=16*1
    }

    /// 🟡 LR1 (anti shard-targeting / HashDoS-parente): la selezione dello shard è
    /// seed-randomizzata PER-ISTANZA. Con `DefaultHasher::new()` (seed fisso) una key
    /// data cadrebbe SEMPRE nello stesso shard in ogni istanza → un attaccante che
    /// conosce le proprie key concentra il flood su 1 shard. Mutation-verify: con seed
    /// fisso `indices` avrebbe 1 solo elemento → l'assert fallisce.
    #[test]
    fn shard_selection_is_seeded_per_instance_lr1() {
        let key = "victim-session-id-42";
        let mut indices = std::collections::HashSet::new();
        for _ in 0..64 {
            let m: ShardedLru<String, u32> = ShardedLru::new(1024);
            indices.insert(m.shard_idx(key));
        }
        // 64 istanze, 16 shard: con seed random P(tutti uguali) ≈ 16^-63 → niente flake.
        assert!(
            indices.len() > 1,
            "LR1: selezione shard predicibile (seed fisso) — {} indici distinti su 64 istanze",
            indices.len()
        );
    }

    /// LR1 (corollario): con lo STESSO `shard_hasher` (stessa istanza), una key è
    /// stabile → cade SEMPRE nello stesso shard (altrimenti i lookup romperebbero).
    #[test]
    fn shard_selection_is_stable_within_instance() {
        let m: ShardedLru<String, u32> = ShardedLru::new(1024);
        let idx = m.shard_idx("k");
        for _ in 0..1000 {
            assert_eq!(m.shard_idx("k"), idx);
        }
        // E coerente fra owned (K) e borrowed (Q): String vs &str → stesso shard.
        let owned = String::from("k");
        assert_eq!(m.shard_idx(&owned), m.shard_idx("k"));
    }

    #[test]
    fn remove_if_removes_only_when_predicate_true() {
        let lru: ShardedLru<&str, u32> = ShardedLru::with_shards(100, 4);
        lru.put("a", 1);
        lru.put("b", 2);
        // pred false → niente rimozione, ritorna None.
        assert_eq!(lru.remove_if(&"a", |v| *v > 10), None);
        assert!(lru.contains(&"a"));
        // pred true → rimuove e ritorna il valore.
        assert_eq!(lru.remove_if(&"b", |v| *v == 2), Some(2));
        assert!(!lru.contains(&"b"));
        // key assente → None.
        assert_eq!(lru.remove_if(&"zzz", |_| true), None);
    }

    #[test]
    fn clear_empties_all_shards() {
        let lru: ShardedLru<u64, u64> = ShardedLru::with_shards(160, 16);
        for i in 0..500 {
            lru.put(i, i);
        }
        assert!(lru.len() > 0);
        lru.clear();
        assert_eq!(lru.len(), 0);
        assert!(lru.is_empty());
        // riusabile dopo clear.
        lru.put(1, 1);
        assert_eq!(lru.len(), 1);
    }

    #[test]
    fn upsert_inserts_then_updates() {
        let lru: ShardedLru<&str, u32> = ShardedLru::with_shards(100, 4);
        lru.upsert("a", || 1, |v| *v += 1);
        lru.with_peek(&"a", |v| assert_eq!(v, Some(&1)));
        lru.upsert("a", || 99, |v| *v += 10); // esistente → update, NON default
        lru.with_peek(&"a", |v| assert_eq!(v, Some(&11)));
        assert_eq!(lru.len(), 1);
    }

    #[test]
    fn bounded_under_key_flood() {
        // SESSION1/EL1: 10_000 key distinte con cap 100 → len ≤ cap (no OOM).
        let lru: ShardedLru<u64, u64> = ShardedLru::with_shards(100, 16);
        for i in 0..10_000u64 {
            lru.upsert(i, || i, |_| {});
        }
        assert!(lru.len() <= lru.capacity(), "len={} cap={}", lru.len(), lru.capacity());
        assert!(lru.len() <= 100);
    }

    #[test]
    fn single_shard_is_true_lru_recency() {
        // 1 shard → LRU globale deterministica. cap 3: A,B,C, poi tocco A,
        // inserisco D → evicta la LRU = B (O(1), non un O(n) scan).
        let lru: ShardedLru<&str, u32> = ShardedLru::with_shards(3, 1);
        lru.put("A", 1);
        lru.put("B", 2);
        lru.put("C", 3);
        assert_eq!(lru.len(), 3);
        lru.with_get_mut(&"A", |v| { if let Some(v) = v { *v += 100; } }); // promote A
        lru.put("D", 4); // evicts LRU = B
        assert_eq!(lru.len(), 3);
        assert!(!lru.contains(&"B"), "B (LRU) deve essere evicted");
        assert!(lru.contains(&"A"));
        assert!(lru.contains(&"C"));
        assert!(lru.contains(&"D"));
    }

    #[test]
    fn retain_drops_non_matching() {
        let lru: ShardedLru<u64, u64> = ShardedLru::with_shards(100, 4);
        for i in 0..20u64 {
            lru.put(i, i);
        }
        lru.retain(|_, v| *v % 2 == 0); // tieni solo i pari
        assert_eq!(lru.len(), 10);
        assert!(lru.contains(&4));
        assert!(!lru.contains(&5));
    }

    #[test]
    fn retain_can_mutate_before_deciding() {
        // `keep` riceve &mut V → può MUTARE l'entry e poi decidere il drop
        // (es. prune di una finestra interna, come fa cross_ip::cleanup_map).
        let lru: ShardedLru<u64, u64> = ShardedLru::with_shards(100, 4);
        for i in 1..=6u64 {
            lru.put(i, i);
        }
        lru.retain(|_, v| {
            *v -= 1; // muta
            *v > 2 // tieni se >2: 1..6 →0,1,2,3,4,5 → restano 3,4,5
        });
        assert_eq!(lru.len(), 3);
        assert!(lru.contains(&6)); // era 6→5 (>2), resta
        assert!(!lru.contains(&3)); // era 3→2 (non >2), droppata
    }

    #[test]
    fn for_each_mut_touches_all_entries() {
        let lru: ShardedLru<u64, u64> = ShardedLru::with_shards(100, 4);
        for i in 0..10u64 {
            lru.put(i, i);
        }
        lru.for_each_mut(|_, v| *v += 1000);
        for i in 0..10u64 {
            lru.with_peek(&i, |v| assert_eq!(v, Some(&(i + 1000))));
        }
        assert_eq!(lru.len(), 10); // for_each_mut non rimuove nulla
    }

    #[test]
    fn with_entry_mut_creates_then_mutates_and_returns() {
        let lru: ShardedLru<u64, u64> = ShardedLru::with_shards(100, 4);
        // assente → crea default(10), muta +1, ritorna il nuovo valore
        let r = lru.with_entry_mut(1, || 10, |v| { *v += 1; *v });
        assert_eq!(r, 11);
        lru.with_peek(&1, |v| assert_eq!(v, Some(&11)));
        // presente → NON usa default, muta l'esistente
        let r2 = lru.with_entry_mut(1, || 999, |v| { *v += 5; *v });
        assert_eq!(r2, 16);
        assert_eq!(lru.len(), 1);
    }

    #[test]
    fn with_entry_mut_evicts_lru_o1_when_full() {
        let lru: ShardedLru<u64, u64> = ShardedLru::with_shards(2, 1); // 1 shard, cap 2
        lru.with_entry_mut(1, || 1, |_| {});
        lru.with_entry_mut(2, || 2, |_| {});
        lru.with_entry_mut(3, || 3, |_| {}); // pieno → evict LRU (1) O(1)
        assert_eq!(lru.len(), 2);
        assert!(!lru.contains(&1));
        assert!(lru.contains(&3));
    }

    #[test]
    fn put_returns_evicted_on_overflow() {
        let lru: ShardedLru<u64, u64> = ShardedLru::with_shards(2, 1);
        assert!(lru.put(1, 1).is_none());
        assert!(lru.put(2, 2).is_none());
        let evicted = lru.put(3, 3); // cap 1 shard pieno → evict LRU (1)
        assert_eq!(evicted, Some((1, 1)));
        assert!(!lru.contains(&1));
    }
}
