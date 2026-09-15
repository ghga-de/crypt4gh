Installation
============

.. highlight:: shell

The sources for EGA cryptor can be downloaded and installed from the `EGA-archive Github repo`_.

.. code-block:: console

    pip install crypt4gh

or install it from sources:

.. code-block:: console

   git clone https://github.com/EGA-archive/crypt4gh
   pip install -r crypt4gh/requirements.txt
   pip install ./crypt4gh
   #
   # or just
   #
   pip install git+https://github.com/EGA-archive/crypt4gh.git


.. _EGA-archive Github repo: https://github.com/EGA-archive/crypt4gh

----

Shell completions
=================

If you want auto-completions, you can install extra scripts with the ``crypt4gh-completions`` utility.

For example, you can install the ``bash`` completion scripts with:

.. code-block:: console

   # Install bash completion in the default location
   crypt4gh-completions install bash
   
   # Or specify the target directory
   crypt4gh-completions install bash --target /etc/bash_completion.d


You can list default locations and what scripts would be installed with:

.. code-block:: console

   crypt4gh-completions show

So far, we provide the ``bash`` and ``zsh`` completions. Help me out with a PR for the other shells.

----

Testsuite
=========

You can run a few tests after installation.
We provide a testsuite simulating, for example, that Bob encrypts a randomly-generated file for Alice and Alice decrypts it.
We use `BATS <https://github.com/bats-core/bats-core>`_ to run the testsuite (so... install bats first).

.. code-block:: console

    cd [path/to/crypt4gh/cloned/repository]
    bats tests

which should output, something along those lines (yes, the testsuite might grow):

.. code-block:: console

   ✓ Bob sends a secret message to Alice, buried in some random data

   ✓ Bob sends a secret (random) 10MB file to Alice
   ✓ Bob sends the testfile secretly to Alice
   ✓ Bob encrypts the testfile for himself and reencrypts it for Alice
   ✓ Bob sends a secret (random) 10MB file to Alice, without his key

   ✓ Bob sends the testfile secretly (with separate header and data) to Alice
   ✓ Bob encrypts the testfile for himself (with separate header) and reencrypts the header for Alice

   ✓ Bob sends a secret (random) 10MB file to Alice, using his ssh-key
   ✓ Bob sends a secret (random) 10MB file to Alice, using Alice's ssh-key
   ✓ Bob sends a secret (random) 10MB file to Alice, both using their ssh-keys

   ✓ Bob sends the testfile secretly to himself and Alice
   ✓ Bob encrypts the testfile for himself and reencrypts it for himself and Alice

   ✓ Bob sends only the Bs from the testfile secretly to Alice
   ✓ Bob sends one A, all Bs, one C, from the testfile secretly to Alice
   ✓ Bob rearranges the encrypted testfile to send one A, all Bs, one C, to Alice

   15 tests, 0 failures
