// Package integrationtest contains end-to-end tests that exercise the
// OpAMP client and server together with the signing package. The tests
// live in a dedicated package outside both subtrees so they can import
// client and server without forcing a build-time edge between the two
// otherwise-independent packages.
package integrationtest
