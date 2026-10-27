package e2e

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests pin the WebDAV semantics of the mock oCIS server (TST-001).
// The mock must behave like a real WebDAV server so the e2e scenarios cannot
// be masked by unconditional success: PUT into a missing parent collection
// must fail with 404, PUT with If-None-Match: * onto an existing object must
// fail with 412, MKCOL on an existing collection must fail with 405, and
// MKCOL with a missing parent must fail with 409 (MKCOL is not recursive).

func mockPut(t *testing.T, base, path string, data []byte, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, base+"/webdav"+path, bytes.NewReader(data))
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func mockMKCOL(t *testing.T, base, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("MKCOL", base+"/webdav"+path, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func mockHEAD(t *testing.T, base, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodHead, base+"/webdav"+path, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// TestMockWebDAV_PUTMissingParentReturns404: a real WebDAV server rejects a
// PUT into a collection that does not exist instead of creating it implicitly.
func TestMockWebDAV_PUTMissingParentReturns404(t *testing.T) {
	webdavServer, _, err := MockOCIS()
	require.NoError(t, err)
	defer webdavServer.Close()

	resp := mockPut(t, webdavServer.URL, "/uploads/no-such-dir/file.txt", []byte("data"), nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"PUT into a missing parent collection must fail with 404 (TST-001)")
}

// TestMockWebDAV_PUTIfNoneMatchExistingReturns412: the bridge sends
// If-None-Match: * for non-overwriting uploads (QLT-002); a real server
// answers 412 when the target already exists.
func TestMockWebDAV_PUTIfNoneMatchExistingReturns412(t *testing.T) {
	webdavServer, _, err := MockOCIS()
	require.NoError(t, err)
	defer webdavServer.Close()

	resp := mockPut(t, webdavServer.URL, "/uploads/existing.txt", []byte("v1"), map[string]string{"If-None-Match": "*"})
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	resp = mockPut(t, webdavServer.URL, "/uploads/existing.txt", []byte("v2"), map[string]string{"If-None-Match": "*"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusPreconditionFailed, resp.StatusCode,
		"PUT with If-None-Match: * onto an existing object must fail with 412 (TST-001)")

	// An unconditional PUT (overwrite) still succeeds.
	resp = mockPut(t, webdavServer.URL, "/uploads/existing.txt", []byte("v2"), nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
}

// TestMockWebDAV_MKCOLSemantics: MKCOL creates a collection (201), fails with
// 405 when the collection already exists, and fails with 409 when the parent
// collection is missing (MKCOL is not recursive).
func TestMockWebDAV_MKCOLSemantics(t *testing.T) {
	webdavServer, _, err := MockOCIS()
	require.NoError(t, err)
	defer webdavServer.Close()

	resp := mockMKCOL(t, webdavServer.URL, "/uploads/mkcol-test")
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	resp = mockMKCOL(t, webdavServer.URL, "/uploads/mkcol-test")
	defer resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode,
		"MKCOL on an existing collection must fail with 405 (TST-001)")

	resp2 := mockMKCOL(t, webdavServer.URL, "/uploads/missing-parent/child")
	defer resp2.Body.Close()
	require.Equal(t, http.StatusConflict, resp2.StatusCode,
		"MKCOL with a missing parent collection must fail with 409 (TST-001)")
}

// TestMockWebDAV_PUTAfterMKCOLSucceeds: after MKCOL creates the parent
// collection, PUT into it succeeds (the happy path the bridge relies on).
func TestMockWebDAV_PUTAfterMKCOLSucceeds(t *testing.T) {
	webdavServer, _, err := MockOCIS()
	require.NoError(t, err)
	defer webdavServer.Close()

	resp := mockMKCOL(t, webdavServer.URL, "/uploads/put-test")
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	resp2 := mockPut(t, webdavServer.URL, "/uploads/put-test/file.txt", []byte("data"), nil)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusCreated, resp2.StatusCode)
}

// TestMockWebDAV_HEADExistence: HEAD distinguishes existing objects and
// collections (200) from missing ones (404); the bridge's collision checks
// and parent-directory creation depend on this.
func TestMockWebDAV_HEADExistence(t *testing.T) {
	webdavServer, _, err := MockOCIS()
	require.NoError(t, err)
	defer webdavServer.Close()

	put := mockPut(t, webdavServer.URL, "/uploads/head-test.txt", []byte("data"), nil)
	require.Equal(t, http.StatusCreated, put.StatusCode)
	put.Body.Close()

	mk := mockMKCOL(t, webdavServer.URL, "/uploads/head-dir")
	require.Equal(t, http.StatusCreated, mk.StatusCode)
	mk.Body.Close()

	for _, path := range []string{"/uploads/head-test.txt", "/uploads/head-dir"} {
		resp := mockHEAD(t, webdavServer.URL, path)
		require.Equal(t, http.StatusOK, resp.StatusCode, "HEAD %s must be 200", path)
		resp.Body.Close()
	}

	resp := mockHEAD(t, webdavServer.URL, "/uploads/missing.txt")
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"HEAD on a missing object must be 404 (TST-001)")
}
