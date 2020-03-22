use std::rc::Rc;
use std::pin::Pin;
use std::cell::RefCell;
use std::future::Future;
use std::task::{Context, Poll};

struct Racer<'a, b> {
    fut1: Pin<Box<dyn Future<Output = b> + 'a>>,
    fut2: Pin<Box<dyn Future<Output = b> + 'a>>,
    default: Rc<RefCell<Option<b>>>,
}

impl <'a, b> Racer<'a, b> {
    fn new(fut1: impl Future<Output = b> + 'a, fut2: impl Future<Output = b> + 'a, default: b) -> Self {
        Racer {
            fut1: Box::pin(fut1),
            fut2: Box::pin(fut2),
            default: Rc::new(RefCell::new(Some(default)))
        }
    }
}

impl <'a, b> Future for Racer<'a, b> {
    type Output = b;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut self_mut = self.get_mut();
        let mut fut1 = &mut self_mut.fut1;
        let mut fut2 = &mut self_mut.fut2;

        let poll1 = Future::poll(fut1.as_mut(), cx);
        let poll2 = Future::poll(fut2.as_mut(), cx);

        match (poll1, poll2) {
            (Poll::Pending, Poll::Pending) => return Poll::Pending,
            (Poll::Ready(res), Poll::Pending) => return Poll::Ready(res),
            (Poll::Pending, Poll::Ready(res)) => return Poll::Ready(res),
            (Poll::Ready(res1), Poll::Ready(res2)) => {
                let default = RefCell::borrow_mut(&self_mut.default).take().unwrap();
                Poll::Ready(default)
            }
        }
    }
}

pub(crate) async fn race<'a, b>(fut1: impl Future<Output = b> + 'a, fut2: impl Future<Output = b> + 'a, default: b) -> b {
    let racer = Racer::new(fut1, fut2, default);
    racer.await
}