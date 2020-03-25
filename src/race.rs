use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

struct Racer<'a, B> {
    fut1: Pin<Box<dyn Future<Output = B> + Send + 'a>>,
    fut2: Pin<Box<dyn Future<Output = B> + Send + 'a>>,
}

impl<'a, B> Racer<'a, B> {
    fn new(
        fut1: impl Future<Output = B> + Send + 'a,
        fut2: impl Future<Output = B> + Send + 'a,
    ) -> Self {
        Racer {
            fut1: Box::pin(fut1),
            fut2: Box::pin(fut2),
        }
    }
}

impl<B> Future for Racer<'_, B> {
    type Output = Option<B>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let self_mut = self.get_mut();
        let fut1 = &mut self_mut.fut1;
        let fut2 = &mut self_mut.fut2;

        let poll1 = fut1.as_mut().poll(cx);
        let poll2 = fut2.as_mut().poll(cx);

        match (poll1, poll2) {
            (Poll::Pending, Poll::Pending) => Poll::Pending,
            (Poll::Ready(res), Poll::Pending) => Poll::Ready(Some(res)),
            (Poll::Pending, Poll::Ready(res)) => Poll::Ready(Some(res)),
            (Poll::Ready(_), Poll::Ready(_)) => Poll::Ready(None),
        }
    }
}

pub(crate) async fn race<B>(
    fut1: impl Future<Output = B> + Send,
    fut2: impl Future<Output = B> + Send,
    default: B,
) -> B {
    Racer::new(fut1, fut2).await.unwrap_or(default)
}
