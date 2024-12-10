# Changelog for scientific

## 0.5.2 -- 2023-11-15

* Fix bug in serde human-readable serialization 
* Improve CI
* Improve tests
* Small optimizations

## 0.5.1 -- 2023-08-30

* Fix 16 and 32 bit only code
* Improve CI
* Improve tests

## 0.5.0 -- 2023-08-03

* Re-Export macro
* Improve documentation
* Change ow the macro works
* Small internal improvements

## 0.2.2 -- 2023-07-15

* Fix sqrt errors
* RPSP now calculates one more digit
* Add more tests
* Several small improvements

## 0.2.1 -- 2023-07-04

* Fix miri errors
* Several small improvements

## 0.2.0 -- 2022-12-15

* Breaking change!
* Rewrite several functions and internals
* Add Rounding to prepare for shorter precision

## 0.1.3 -- 2022-11-09

* Fix clippy warnings
* Remove patch level precision of the dependencies
* Reorder code
* Use actual end for static Ptr/debug
* Use NonNull instead of a raw ptr
* Add TryFrom for u/isize, improve From<u/isize>
* Change to cargo rdme, small adaptions to the doc
* Move tests to usual directory
* Remove doc and test from conditional checks
* Use docsrs to document features

## 0.1.2 -- 2021-07-08

* Fixed serialization
* Support rounding
* Several small improvements

## 0.1.0 -- 2021-06-25

* Initial release
