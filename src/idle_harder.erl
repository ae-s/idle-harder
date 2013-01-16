-module(idle_harder).
-behaviour(application).
-export([start/2, stop/1, start_pool/3,
	 run/2, sync_queue/2, async_queue/2, stop_pool/1]).

start(normal, _Args) ->
    ok.

stop(_State) ->
    ok.

start_pool(_, _, _) ->
    ok.
run(_, _) ->
    ok.
sync_queue(_, _) ->
    ok.
async_queue(_, _) ->
    ok.
stop_pool(_) ->
    ok.
