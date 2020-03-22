use std::rc::Rc;
use std::pin::Pin;
use std::cell::RefCell;
use std::future::Future;
use std::task::{Context, Poll};

struct Racer<'a, B> {
    fut1: Pin<Box<dyn Future<Output = B> + 'a>>,
    fut2: Pin<Box<dyn Future<Output = B> + 'a>>,
    default: Rc<RefCell<Option<B>>>,
}

impl <'a, B> Racer<'a, B> {
    fn new(fut1: impl Future<Output = B> + 'a, fut2: impl Future<Output = B> + 'a, default: B) -> Self {
        Racer {
            fut1: Box::pin(fut1),
            fut2: Box::pin(fut2),
            default: Rc::new(RefCell::new(Some(default)))
        }
    }
}

impl <'a, B> Future for Racer<'a, B> {
    type Output = B;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let self_mut = self.get_mut();
        let fut1 = &mut self_mut.fut1;
        let fut2 = &mut self_mut.fut2;

        let poll1 = Future::poll(fut1.as_mut(), cx);
        let poll2 = Future::poll(fut2.as_mut(), cx);

        match (poll1, poll2) {
            (Poll::Pending, Poll::Pending) => return Poll::Pending,
            (Poll::Ready(res), Poll::Pending) => return Poll::Ready(res),
            (Poll::Pending, Poll::Ready(res)) => return Poll::Ready(res),
            (Poll::Ready(_), Poll::Ready(_)) => {
                let default = RefCell::borrow_mut(&self_mut.default).take().unwrap();
                Poll::Ready(default)
            }
        }
    }
}

pub(crate) async fn race<'a, B>(fut1: impl Future<Output = B> + 'a, fut2: impl Future<Output = B> + 'a, default: B) -> B {
    let racer = Racer::new(fut1, fut2, default);
    racer.await
}