mod proxy;

use worker::*;

macro_rules! trace_log {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            worker::console_log!($($arg)*);
        }
    }};
}

macro_rules! trace_error {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            worker::console_error!($($arg)*);
        }
    }};
}

pub(crate) use trace_error;
pub(crate) use trace_log;

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    if proxy::ProxyService::is_websocket_request(&req) {
        return proxy::ProxyService::new(env)?.handle(req, ctx).await;
    }

    Response::ok("vlpo-worker-rs kernel is running!")
}
