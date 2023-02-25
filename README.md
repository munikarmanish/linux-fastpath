# Linux network fast path

In this project, we try to implement a fast path for TCP an UDP network stack
that accelerates the processing of subsequent packets of a flow once the
destination socket of the first packet (of that flow) has been identified. This
is especially beneficial for virtual overlay (encapsulated) networks that have
multiple stages (virtual devices) in its data path.

More documentation coming soon... :)
