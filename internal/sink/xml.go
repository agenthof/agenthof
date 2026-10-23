package sink

import "encoding/xml"

// The S3 response documents the transport reads. The root names are matched
// in any namespace (AWS, MinIO and Ceph all emit the 2006-03-01 one); every
// child is matched by local name, so a namespaced document decodes as a
// plain one does.

// listVersionsResult is ListObjectVersions' page. Entries keeps <Version>
// and <DeleteMarker> in document order — the ",any" rule collects every
// child the named fields do not claim; the metadata children it also
// collects (Name, Prefix, MaxKeys, …) are dropped by name.
type listVersionsResult struct {
	XMLName             xml.Name    `xml:"ListVersionsResult"`
	IsTruncated         bool        `xml:"IsTruncated"`
	NextKeyMarker       string      `xml:"NextKeyMarker"`
	NextVersionIDMarker string      `xml:"NextVersionIdMarker"`
	Entries             []listEntry `xml:",any"`
}

// listEntry is one <Version> or <DeleteMarker>; XMLName.Local says which.
type listEntry struct {
	XMLName      xml.Name
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	Size         int64  `xml:"Size"`
}

// retentionResult is GetObjectRetention's body.
type retentionResult struct {
	XMLName         xml.Name `xml:"Retention"`
	Mode            string   `xml:"Mode"`
	RetainUntilDate string   `xml:"RetainUntilDate"`
}

// objectLockConfiguration is GetObjectLockConfiguration's body.
type objectLockConfiguration struct {
	XMLName           xml.Name `xml:"ObjectLockConfiguration"`
	ObjectLockEnabled string   `xml:"ObjectLockEnabled"`
}

// errorResult is the <Error> document a refused request carries; only the
// code is read (the message is server text, never repeated).
type errorResult struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
}
