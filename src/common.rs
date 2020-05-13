use futures::task::Waker;
use futures::task::{Context, Poll};
use futures::Future;
use hashbrown::HashMap;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub trait FlattenResult<T, E> {
    fn flatten_result(self) -> Result<T, E>;
}

impl<T, E, Ex: Into<E>> FlattenResult<T, E> for Result<Result<T, E>, Ex> {
    fn flatten_result(self) -> Result<T, E> {
        match self {
            Ok(r) => r,
            Err(e) => Err(e.into()),
        }
    }
}

pub struct TriggerFut<T: Clone> {
    pub created_at: Instant,
    future_state: Arc<Mutex<FutureState<T>>>,
    future_id: usize,
}

impl<T: Clone> TriggerFut<T> {
    pub fn is_pending(&self) -> bool {
        (*self.future_state.lock().unwrap()).value.is_none()
    }

    pub fn ready(&mut self, value: T) {
        if self.is_pending() {
            (*self.future_state.lock().unwrap()).ready(value);
        }
    }
}

impl<T: Clone> Default for TriggerFut<T> {
    fn default() -> Self {
        TriggerFut {
            created_at: Instant::now(),
            future_state: Arc::new(Mutex::new(FutureState::default())),
            future_id: usize::max_value(),
        }
    }
}

impl<T: Clone> Debug for TriggerFut<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("TriggerFut {{ id: {:?} }}", self.future_id))
    }
}

impl<T: Clone> Clone for TriggerFut<T> {
    fn clone(&self) -> Self {
        TriggerFut {
            created_at: self.created_at.clone(),
            future_state: self.future_state.clone(),
            future_id: self.future_state.lock().unwrap().next_id(),
        }
    }
}

impl<T: Clone> Drop for TriggerFut<T> {
    fn drop(&mut self) {
        let mut future_state = self.future_state.lock().unwrap();
        future_state.remove(&self.future_id);
    }
}

impl<T: Clone> Future for TriggerFut<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let value = { self.future_state.lock().unwrap().value().cloned() };
        match value {
            Some(t) => Poll::Ready(t),
            _ => {
                let mut future_state = self.future_state.lock().unwrap();
                future_state.insert(self.future_id, cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

pub struct FutureState<T> {
    value: Option<T>,
    seq: AtomicUsize,
    waker_map: HashMap<usize, Waker>,
}

impl<T> FutureState<T> {
    pub fn ready(&mut self, t: T) {
        self.value.replace(t);
        self.waker_map.values_mut().for_each(|w| w.wake_by_ref());
    }

    #[inline]
    pub fn insert(&mut self, id: usize, waker: Waker) {
        self.waker_map.insert(id, waker);
    }

    #[inline]
    pub fn remove(&mut self, id: &usize) -> Option<Waker> {
        self.waker_map.remove(id)
    }
}

impl<T> FutureState<T> {
    #[inline]
    pub fn next_id(&self) -> usize {
        self.seq.fetch_add(1, SeqCst)
    }

    #[inline]
    pub fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }
}

impl<T> Default for FutureState<T> {
    fn default() -> Self {
        FutureState {
            value: None,
            seq: AtomicUsize::new(0),
            waker_map: HashMap::new(),
        }
    }
}

impl<T> Debug for FutureState<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let resolved = self.value().map(|_| true).unwrap_or(false);
        write!(f, "FutureState {{ resolved: {} }}", resolved)
    }
}
