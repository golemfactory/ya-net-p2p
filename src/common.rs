use crate::error::SessionError;
use futures::task::Waker;
use futures::task::{Context, Poll};
use futures::Future;
use hashbrown::HashMap;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Mutex};

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
    inner_state: Arc<Mutex<T>>,
    future_state: Arc<Mutex<FutureState<bool>>>,
    future_id: usize,
}

impl<T: Clone> TriggerFut<T> {
    pub fn new(inner: T) -> Self {
        TriggerFut {
            inner_state: Arc::new(Mutex::new(inner)),
            future_state: Arc::new(Mutex::new(FutureState::default())),
            future_id: usize::max_value(),
        }
    }

    pub fn pending(&self) -> bool {
        (*self.future_state.lock().unwrap()).value().is_none()
    }

    pub fn success(&mut self) {
        if self.pending() {
            (*self.future_state.lock().unwrap()).ready(true);
        }
    }

    pub fn failure(&mut self) {
        if self.pending() {
            (*self.future_state.lock().unwrap()).ready(false);
        }
    }
}

impl<T: Clone + Debug> Debug for TriggerFut<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("TriggerFut {{ id: {:?} }}", self.future_id))
    }
}

impl<T: Clone> Clone for TriggerFut<T> {
    fn clone(&self) -> Self {
        TriggerFut {
            inner_state: self.inner_state.clone(),
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
    type Output = crate::Result<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let value = { self.future_state.lock().unwrap().value().cloned() };
        match value {
            Some(true) => Poll::Ready(Ok(self.inner_state.lock().unwrap().clone())),
            Some(false) => Poll::Ready(Err(SessionError::Disconnected.into())),
            _ => {
                let mut future_state = self.future_state.lock().unwrap();
                future_state.insert(self.future_id, cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

#[derive(Debug)]
pub struct FutureState<T: Debug> {
    value: Option<T>,
    seq: AtomicUsize,
    waker_map: HashMap<usize, Waker>,
}

impl<T: Debug> FutureState<T> {
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

impl<T: Debug> FutureState<T> {
    #[inline]
    pub fn next_id(&self) -> usize {
        self.seq.fetch_add(1, SeqCst)
    }

    #[inline]
    pub fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }
}

impl<T: Debug> Default for FutureState<T> {
    fn default() -> Self {
        FutureState {
            value: None,
            seq: AtomicUsize::new(0),
            waker_map: HashMap::new(),
        }
    }
}
