---
title: RabbitMQ tutorial - Routing
---

import TutorialsHelp from '@site/src/components/Tutorials/TutorialsHelp.md';
import T4DiagramDirectX from '@site/src/components/Tutorials/T4DiagramDirectX.md';
import T4DiagramMultipleBindings from '@site/src/components/Tutorials/T4DiagramMultipleBindings.md';
import T4DiagramFull from '@site/src/components/Tutorials/T4DiagramFull.md';

# RabbitMQ tutorial - Routing

## Routing
### (using the [Objective-C client][client])

<TutorialsHelp/>

In the [previous tutorial][previous] we built a
simple logging system. We were able to broadcast log messages to many
receivers.

In this tutorial we're going to add a feature to it - we're going to
make it possible to subscribe only to a subset of the messages. For
example, we will be able to direct only critical error messages to the
log file (to save disk space), while still being able to print all of
the log messages on the console.


Bindings
--------

In previous examples we were already creating bindings. You may recall
code like:

```objectivec
[q bind:exchange];
```

A binding is a relationship between an exchange and a queue. This can
be simply read as: the queue is interested in messages from this
exchange.

Bindings can take an extra `routingKey` parameter. To avoid the
confusion with an `RMQExchange publish:` parameter we're going to call it a
`binding key`. This is how we could create a binding with a key:

```objectivec
[q bind:exchange routingKey:@"black"];
```

The meaning of a binding key depends on the exchange type. The
`fanout` exchanges, which we used previously, simply ignored its
value.

Direct exchange
---------------

Our logging system from the previous tutorial broadcasts all messages
to all consumers. We want to extend that to allow filtering messages
based on their severity. For example we may want the script which is
writing log messages to the disk to only receive critical errors, and
not waste disk space on warning or info log messages.

We were using a `fanout` exchange, which doesn't give us much
flexibility - it's only capable of mindless broadcasting.

We will use a `direct` exchange instead. The routing algorithm behind
a `direct` exchange is simple - a message goes to the queues whose
`binding key` exactly matches the `routing key` of the message.

To illustrate that, consider the following setup:

<T4DiagramDirectX/>

In this setup, we can see the `direct` exchange `X` with two queues bound
to it. The first queue is bound with binding key `orange`, and the second
has two bindings, one with binding key `black` and the other one
with `green`.

In such a setup a message published to the exchange with a routing key
`orange` will be routed to queue `Q1`. Messages with a routing key of `black`
or `green` will go to `Q2`. All other messages will be discarded.


Multiple bindings
-----------------
<T4DiagramMultipleBindings/>

It is perfectly legal to bind multiple queues with the same binding
key. In our example we could add a binding between `X` and `Q1` with
binding key `black`. In that case, the `direct` exchange will behave
like `fanout` and will broadcast the message to all the matching
queues. A message with routing key `black` will be delivered to both
`Q1` and `Q2`.


Emitting logs
-------------

We'll use this model for our logging system. Instead of `fanout` we'll
send messages to a `direct` exchange. We will supply the log severity as
a `routing key`. That way the receiving method will be able to select
the severity it wants to receive. Let's focus on emitting logs
first.

As always, we need to create an exchange first:

```objectivec
[ch direct:@"logs"];
```

And we're ready to send a message:

```objectivec
RMQExchange *x = [ch direct:@"logs"];
[x publish:[msg dataUsingEncoding:NSUTF8StringEncoding] routingKey:severity];
```

To simplify things we will assume that 'severity' can be one of
'info', 'warning', 'error'.


Subscribing
-----------

Receiving messages will work just like in the previous tutorial, with
one exception - we're going to create a new binding for each severity
we're interested in.

```objectivec
RMQQueue *q = [ch queue:@"" options:RMQQueueDeclareExclusive];

NSArray *severities = @[@"error", @"warning", @"info"];
for (NSString *severity in severities) {
    [q bind:x routingKey:severity];
}
```


Putting it all together
-----------------------

<T4DiagramFull/>


The code for the `emitLogDirect` method:

```objectivec
- (void)emitLogDirect:(NSString *)msg severity:(NSString *)severity {
    RMQConnection *conn = [[RMQConnection alloc] initWithDelegate:[RMQConnectionDelegateLogger new]];
    [conn start];

    id&lt;RMQChannel&gt; ch = [conn createChannel];
    RMQExchange *x    = [ch direct:@"direct_logs"];

    [x publish:[msg dataUsingEncoding:NSUTF8StringEncoding] routingKey:severity];
    NSLog(@"Sent '%@'", msg);

    [conn close];
}
```

The code for `receiveLogsDirect`:

```objectivec
- (void)receiveLogsDirect {
    RMQConnection *conn = [[RMQConnection alloc] initWithDelegate:[RMQConnectionDelegateLogger new]];
    [conn start];

    id&lt;RMQChannel&gt; ch = [conn createChannel];
    RMQExchange *x    = [ch direct:@"direct_logs"];
    RMQQueue *q       = [ch queue:@"" options:RMQQueueDeclareExclusive];

    NSArray *severities = @[@"error", @"warning", @"info"];
    for (NSString *severity in severities) {
        [q bind:x routingKey:severity];
    }

    NSLog(@"Waiting for logs.");

    [q subscribe:^(RMQMessage * _Nonnull message) {
        NSLog(@"%@:%@", message.routingKey, [[NSString alloc] initWithData:message.body encoding:NSUTF8StringEncoding]);
    }];
}
```

To emit an `error` log message just call:

```objectivec
[self emitLogDirect:@"Hi there!" severity:@"error"];
```

([source code][source])

Move on to [tutorial 5][next] to find out how to listen
for messages based on a pattern.

[client]:https://github.com/rabbitmq/rabbitmq-objc-client
[previous]:./tutorial-three-objectivec
[next]:./tutorial-five-objectivec
[source]:https://github.com/rabbitmq/rabbitmq-tutorials/blob/main/objective-c/tutorial4/tutorial4/ViewController.m
