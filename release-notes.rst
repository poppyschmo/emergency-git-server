Release Notes
-------------

This script has finally been **retired** (good riddance!). The package itself
may disappear from PyPI on or after January 1, 2021, but the repo will remain.
See the gitweb_ and the `Git Tools`_ wiki pages for many superior alternatives.

.. _gitweb: https://git.wiki.kernel.org/index.php/Gitweb
.. _`Git Tools`: https://git.wiki.kernel.org/index.php/InterfacesFrontendsAndTools


0.1
~~~
- The usable but unmaintainable old master branch has been swapped out with a
  less disgusting and less stable dev branch. Adherence to web standards is
  still largely ignored, but at least those oversights are now somewhat visible
  instead of hidden away in a tangle of rotten pasta.

- Some things that used to work are probably now **broken**. To revert, go for
  package version ``0.0.8``.

- The environment options ``FIRST_CHILD_OK``, ``ENFORCE_DOTGIT``, and
  ``CREATE_MISSING``, have been removed. The script now behaves as if the
  latter two were permanently enabled. Some of the functionality provided by
  the third can now be gotten by enabling ``ALLOW_CREATION``, which allows
  for initializing new repos via "out-of-band" (non-Git-related) HTTP request.
