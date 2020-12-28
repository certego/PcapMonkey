zeek Module for Detecting Cryptocurrency (Bitcoin) Mining Hosts
==============================================================

This script module for zeek can detect Bitcoin, Litecoin, PPCoin, or
other cryptocurrency mining traffic that uses `getwork
<https://en.bitcoin.it/wiki/Getwork>`_, `getblocktemplate
<https://en.bitcoin.it/wiki/Getblocktemplate>`_, or `Stratum
<http://mining.bitcoin.cz/stratum-mining/>`_ mining protocols over TCP
or HTTP.  Note that the module cannot currently detect the Bitcoin P2P
protocol, which is different from the mining protocols.

See mining.zeek for more details on how it works.

Installation
------------

Via `zeek-pkg <http://zeek-package-manager.readthedocs.io/en/stable/>`_::

    zeek-pkg install jsiwek/zeek_bitcoin

Manually::

    cd <prefix>/share/zeek/site
    git clone https://github.com/jsiwek/zeek_bitcoin.git bitcoin
    echo "@load bitcoin" >> local.zeek
