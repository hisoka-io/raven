//! Parameter set 2: a one-row packing key per session, 32-bit kernels, one record per query.
//!
//! A shard's table keeps the cells it was folded from, so a response is always computed from
//! the cells its table was built from. A seat is the client's key in transform form, 16 KiB.
//! Queries run on one fixed pool shared by every batch in flight, so the threads computing
//! responses never exceed its size however many batches arrive at once.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use howl_wire::{
    KeySource, P16Batch, CELL_BYTES, LADDER, P16_KEY_BYTES, P16_QUERY_BYTES, P16_RESPONSE_BYTES,
    RECORD_BYTES,
};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use raven_inspire::special_modulus::{KeySeat, PackingKey, Params, Query, Server, ShardTable};
use raven_inspire_session::SessionStoreLimits;

use crate::engine::{EngineError, Refusal};

fn scheme(e: impl std::fmt::Display) -> EngineError {
    EngineError::Scheme(e.to_string())
}

struct Seat {
    seat: Arc<KeySeat>,
    expires_at: Instant,
}

/// Seated keys by handle. Handles are drawn at random, so a handle from before a restart
/// names no seat after it.
struct Seats {
    limits: SessionStoreLimits,
    seats: Mutex<HashMap<u64, Seat>>,
    handles: Mutex<ChaCha20Rng>,
}

impl Seats {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Seat>> {
        self.seats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn register(&self, seat: KeySeat, now: Instant) -> Result<u64, Refusal> {
        let mut seats = self.lock();
        if seats.len() >= self.limits.max_sessions {
            seats.retain(|_, s| s.expires_at > now);
        }
        if seats.len() >= self.limits.max_sessions {
            return Err(Refusal::Full(format!(
                "all {} session seats are taken",
                self.limits.max_sessions
            )));
        }
        let mut handles = self
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let handle = loop {
            let h = handles.next_u64();
            if !seats.contains_key(&h) {
                break h;
            }
        };
        seats.insert(
            handle,
            Seat {
                seat: Arc::new(seat),
                expires_at: now + self.limits.ttl,
            },
        );
        Ok(handle)
    }

    fn resolve_renewing(&self, handle: u64, now: Instant) -> Result<Arc<KeySeat>, Refusal> {
        let mut seats = self.lock();
        match seats.get_mut(&handle) {
            Some(s) if s.expires_at > now => {
                s.expires_at = now + self.limits.ttl;
                Ok(Arc::clone(&s.seat))
            }
            _ => Err(Refusal::Session(format!(
                "session {handle} is expired or unknown"
            ))),
        }
    }

    fn sweep(&self, now: Instant) -> usize {
        let mut seats = self.lock();
        let before = seats.len();
        seats.retain(|_, s| s.expires_at > now);
        before - seats.len()
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// A fixed set of threads taking jobs from one queue; they exit when the pool is dropped. The
/// queue has no bound of its own: a batch holds its route's permit until its jobs are done, so
/// it holds at most the permits' count of batches.
struct Pool {
    jobs: mpsc::Sender<Job>,
    threads: usize,
    busy: Arc<Busy>,
}

/// Jobs running now, and the most ever at once.
#[derive(Default)]
struct Busy {
    now: AtomicUsize,
    peak: AtomicUsize,
}

impl Pool {
    fn new(threads: usize) -> Result<Self, EngineError> {
        let threads = threads.max(1);
        let (jobs, queue) = mpsc::channel::<Job>();
        let queue = Arc::new(Mutex::new(queue));
        let busy = Arc::new(Busy::default());
        for i in 0..threads {
            let queue = Arc::clone(&queue);
            let busy = Arc::clone(&busy);
            std::thread::Builder::new()
                .name(format!("respond-{i}"))
                .spawn(move || loop {
                    let job = queue
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv();
                    let Ok(job) = job else { return };
                    let now = busy.now.fetch_add(1, Ordering::SeqCst) + 1;
                    busy.peak.fetch_max(now, Ordering::SeqCst);
                    // A job that panics drops its result sender, which its batch reports.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                    busy.now.fetch_sub(1, Ordering::SeqCst);
                })
                .map_err(EngineError::Io)?;
        }
        Ok(Self {
            jobs,
            threads,
            busy,
        })
    }
}

/// The set-2 half of the engine.
pub(crate) struct Single {
    server: Arc<Server>,
    crs: Vec<u8>,
    seats: Seats,
    pool: Pool,
}

impl std::fmt::Debug for Single {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Single")
            .field("kernel", &self.server.kernel())
            .field("sessions", &self.sessions())
            .field("respond_threads", &self.pool.threads)
            .field("respond_peak", &self.pool.busy.peak.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Single {
    pub(crate) fn new(
        limits: SessionStoreLimits,
        respond_threads: usize,
    ) -> Result<Self, EngineError> {
        if limits.max_sessions == 0 {
            return Err(EngineError::Scheme("no session seats".to_owned()));
        }
        let params = Params::ring2048_cell256();
        let sizes = (
            params.cell_bytes,
            params.record_bytes,
            params.key_bytes(),
            params.query_bytes(),
            params.response_bytes(),
        );
        if sizes
            != (
                CELL_BYTES,
                RECORD_BYTES,
                P16_KEY_BYTES,
                P16_QUERY_BYTES,
                P16_RESPONSE_BYTES,
            )
        {
            return Err(EngineError::Scheme(format!(
                "the library's set-2 sizes {sizes:?} are not the wire's"
            )));
        }
        let server = Arc::new(Server::new(&params).map_err(scheme)?);
        let pool = Pool::new(respond_threads)?;
        tracing::info!(kernel = ?server.kernel(), respond_threads = pool.threads, "parameter set 2");
        Ok(Self {
            crs: howl_wire::p16_crs(params.key_mask_version),
            server,
            seats: Seats {
                limits,
                seats: Mutex::new(HashMap::new()),
                handles: Mutex::new(ChaCha20Rng::from_entropy()),
            },
            pool,
        })
    }

    /// The params answer's key material: the key-mask version keys are seated under.
    pub(crate) fn crs(&self) -> &[u8] {
        &self.crs
    }

    pub(crate) fn limits(&self) -> SessionStoreLimits {
        self.seats.limits
    }

    pub(crate) fn sessions(&self) -> usize {
        self.seats.lock().len()
    }

    pub(crate) fn sweep(&self) -> usize {
        self.seats.sweep(Instant::now())
    }

    pub(crate) fn encode(&self, cells: &[u8]) -> Result<ShardTable, EngineError> {
        self.server.table(cells).map_err(scheme)
    }

    /// A key upload, seated.
    pub(crate) fn seat(&self, key: &[u8]) -> Result<KeySeat, String> {
        let key = PackingKey::from_bytes(self.server.params(), key)
            .map_err(|e| format!("body does not decode: {e}"))?;
        self.server
            .seat(&key)
            .map_err(|e| format!("body does not decode: {e}"))
    }

    pub(crate) fn register(&self, seat: KeySeat) -> Result<u64, Refusal> {
        self.seats.register(seat, Instant::now())
    }

    /// The most pool threads ever computing at once.
    #[cfg(test)]
    pub(crate) fn peak_busy(&self) -> usize {
        self.pool.busy.peak.load(Ordering::SeqCst)
    }

    /// Answer every query of `batch` against its shard's table, in order.
    pub(crate) fn respond(
        &self,
        tables: &[&Arc<ShardTable>],
        shards: usize,
        batch: &P16Batch,
    ) -> Result<Vec<Vec<u8>>, Refusal> {
        let n = batch.queries.len();
        if !LADDER.contains(&n) {
            return Err(Refusal::NotALadderStep(n));
        }
        let mut chosen = Vec::with_capacity(n);
        for q in &batch.queries {
            let table = tables.get(q.shard as usize).ok_or(Refusal::Stale {
                shard: q.shard,
                shards,
            })?;
            chosen.push(Arc::clone(table));
        }
        let seat = match &batch.key {
            KeySource::Session(handle) => self.seats.resolve_renewing(*handle, Instant::now())?,
            KeySource::Inline(key) => Arc::new(self.seat(key).map_err(Refusal::Malformed)?),
        };
        let params = self.server.params();
        let queries = batch
            .queries
            .iter()
            .map(|q| Query::from_bytes(params, &q.query))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Refusal::Malformed(e.to_string()))?;
        // One query is one job; the batch waits for all of its own.
        let (done, results) = mpsc::channel();
        for (i, (table, query)) in chosen.into_iter().zip(queries).enumerate() {
            let (server, seat, done) = (Arc::clone(&self.server), Arc::clone(&seat), done.clone());
            let job: Job = Box::new(move || {
                let response = server
                    .respond(&table, &seat, &query)
                    .and_then(|r| r.to_bytes(server.params()))
                    .map_err(|e| Refusal::Malformed(e.to_string()));
                let _ = done.send((i, response));
            });
            if self.pool.jobs.send(job).is_err() {
                return Err(Refusal::Malformed("the respond pool is gone".into()));
            }
        }
        drop(done);
        let mut slots: Vec<Option<Result<Vec<u8>, Refusal>>> = (0..n).map(|_| None).collect();
        for (i, response) in results {
            if let Some(slot) = slots.get_mut(i) {
                *slot = Some(response);
            }
        }
        slots
            .into_iter()
            .map(|s| {
                s.unwrap_or_else(|| Err(Refusal::Malformed("a response did not finish".into())))
            })
            .collect()
    }
}

// A served cell is a record and zero padding, which set 2's tables require.
const _: () = assert!(RECORD_BYTES == howl_record::RECORD_BYTES);

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use raven_inspire::special_modulus::{Client, Params};
    use std::time::Duration;

    fn limits() -> SessionStoreLimits {
        SessionStoreLimits {
            max_sessions: 64,
            ttl: Duration::from_secs(600),
        }
    }

    #[test]
    fn concurrent_batches_never_compute_on_more_threads_than_the_pool_holds() {
        const POOL: usize = 2;
        let single = Single::new(limits(), POOL).expect("single");
        let tables: Vec<Arc<ShardTable>> = (0..4u8)
            .map(|s| {
                let mut cells = vec![0u8; 8 * CELL_BYTES];
                for (m, cell) in cells.as_chunks_mut::<CELL_BYTES>().0.iter_mut().enumerate() {
                    cell[..RECORD_BYTES].fill(s.wrapping_mul(31).wrapping_add(m as u8));
                }
                Arc::new(single.encode(&cells).expect("table"))
            })
            .collect();
        let refs: Vec<&Arc<ShardTable>> = tables.iter().collect();
        let set = Params::ring2048_cell256();
        let batches: Vec<(Client, P16Batch)> = (0..8)
            .map(|b| {
                let mut client = Client::new(&set).expect("client");
                let key = client.packing_key().to_bytes(&set).expect("key");
                let handle = single
                    .register(single.seat(&key).expect("seat"))
                    .expect("register");
                let queries = (0..16)
                    .map(|i| howl_wire::P16Query {
                        shard: ((b + i) % 4) as u32,
                        query: client
                            .query((b + i) % 8)
                            .expect("q")
                            .to_bytes(&set)
                            .expect("b"),
                    })
                    .collect();
                let batch = P16Batch {
                    key: KeySource::Session(handle),
                    queries,
                };
                (client, batch)
            })
            .collect();
        let answers: Vec<Vec<Vec<u8>>> = std::thread::scope(|scope| {
            let workers: Vec<_> = batches
                .iter()
                .map(|(_, batch)| scope.spawn(|| single.respond(&refs, 4, batch).expect("respond")))
                .collect();
            workers
                .into_iter()
                .map(|w| w.join().expect("join"))
                .collect()
        });
        // Every response decodes to its own row.
        for (b, ((client, _), responses)) in batches.iter().zip(&answers).enumerate() {
            for (i, bytes) in responses.iter().enumerate() {
                let response = raven_inspire::special_modulus::Response::from_bytes(&set, bytes)
                    .expect("response");
                let record = client.decode(&response).expect("decode");
                let (s, m) = (((b + i) % 4) as u8, ((b + i) % 8) as u8);
                assert!(record
                    .iter()
                    .all(|&x| x == s.wrapping_mul(31).wrapping_add(m)));
            }
        }
        let peak = single.peak_busy();
        assert!(peak <= POOL, "{peak} threads computed at once, pool {POOL}");
        assert_eq!(peak, POOL, "the pool was never full under 8 batches");
    }
}
