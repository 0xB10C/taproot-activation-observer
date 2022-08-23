# taproot-activation-observer

This is a quick and dirty script to monitor taproot activation.
See my [Monitoring Taproot Activation](https://b10c.me/projects/019-taproot-activation-monitoring) blog post for more details.

If you'd happen to try to run this, you'd need a Bitcoin Core with a patched ZMQ publisher (https://github.com/0xB10C/bitcoin/tree/v22.0-rawtx2).
I ran this with two terminals side by side and started it once with `rawtxfee` for taproot transactions and once with `rawblock` for recent blocks. 
I've archived this repository to make clear that I don't maintain, develop, or support this anymore.
