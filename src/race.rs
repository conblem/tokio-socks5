use std::pin::Pin;
use std::future::Future;
use std::borrow::BorrowMut;
use std::task::{Context, Poll};

struct Racer<'a, B> {
    fut1: Pin<Box<dyn Future<Output = B> + 'a>>,
    fut2: Pin<Box<dyn Future<Output = B> + 'a>>,
    default: Box<Option<B>>
}

impl <'a, B> Racer<'a, B> {
    fn new(fut1: impl Future<Output = B> + 'a, fut2: impl Future<Output = B> + 'a, default: B) -> Self {
        Racer {
            fut1: Box::pin(fut1),
            fut2: Box::pin(fut2),
            default: Box::new(Some(default))
        }
    }
}

impl <B> Future for Racer<'_, B> {
    type Output = B;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let self_mut = self.get_mut();
        let fut1 = &mut self_mut.fut1;
        let fut2 = &mut self_mut.fut2;

        let poll1 = fut1.as_mut().poll(cx);
        let poll2 = fut2.as_mut().poll(cx);

        match (poll1, poll2) {
            (Poll::Pending, Poll::Pending) => Poll::Pending,
            (Poll::Ready(res), Poll::Pending) => Poll::Ready(res),
            (Poll::Pending, Poll::Ready(res)) => Poll::Ready(res),
            (Poll::Ready(_), Poll::Ready(_)) => {
                let default: &mut Option<B> = &mut self_mut.default.borrow_mut();
                Poll::Ready(default.take().unwrap())
            }
        }
    }
}

pub(crate) async fn race<B>(fut1: impl Future<Output = B>, fut2: impl Future<Output = B>, default: B) -> B {
    let racer = Racer::new(fut1, fut2, default);
    racer.await
}