// Package sink is the S3 Object Lock backend of sink: worm — the protected,
// write-once copy of every sealed segment. It is built in three layers so
// the compliance rule and the wire client can change independently:
//
//   - objectStore (store.go): the minimal transport line — five storage
//     operations in storage-neutral terms (put locked, get, retention, lock
//     configuration, list versions). Nothing of HTTP or SigV4 crosses it.
//   - sigv4Store (s3.go, sigv4.go, xml.go): the one implementation shipped —
//     the five S3 REST calls, SigV4-signed, stdlib only; no SDK.
//   - S3 (sink.go): the sink logic over an objectStore — control.SinkWriter
//     and control.SinkReader, the oldest-version rule that makes the first
//     version at a key the seal's own, and the read-back that makes "confirmed"
//     mean read, never assumed. It never sees a request.
package sink
