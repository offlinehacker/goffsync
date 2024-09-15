package syncclient

type loginErrorResponseSchema struct {
	Code    int    `json:"code"`
	ErrNo   int    `json:"errno"`
	Error   string `json:"error"`
	Message string `json:"message"`
	Info    string `json:"info"`
	Email   string `json:"email"`
}

type signCertRequestSchemaPKey struct {
	Algorithm string `json:"algorithm"`
	P         string `json:"p"`
	Q         string `json:"q"`
	G         string `json:"g"`
	Y         string `json:"y"`
}

type signCertRequestSchema struct {
	PublicKey signCertRequestSchemaPKey `json:"publicKey"`
	Duration  int64                     `json:"duration"`
}

type signCertResponseSchema struct {
	Certificate string `json:"cert"`
}

type hawkCredResponseSchema struct {
	ID            string `json:"id"`
	Key           string `json:"key"`
	UID           int64  `json:"uid"`
	APIEndpoint   string `json:"api_endpoint"`
	Duration      int64  `json:"duration"`
	HashAlgorithm string `json:"hashalg"`
	HashedFxAUID  string `json:"hashed_fxa_uid"`
	NodeType      string `json:"node_type"`
}

type deletedPayloadData struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

type listRecordsIDsResponseSchema []string

type listRecordsResponseSchema []recordsResponseSchema

type recordsResponseSchema struct {
	ID        string  `json:"id"`
	Modified  float64 `json:"modified"`
	Payload   string  `json:"payload"`
	SortIndex int64   `json:"sortIndex"`
	TTL       *int64  `json:"ttl"`
}

type recordsRequestSchema struct {
	ID        *string `json:"id"`
	SortIndex *int64  `json:"sortindex,omitempty"`
	Payload   *string `json:"payload,omitempty"`
	TTL       *int64  `json:"ttl,omitempty"`
}

type sessionStatusResponseSchema struct {
	State  string `json:"state"`
	UserID string `json:"uid"`
}

type scopedKeyDataRequestSchema struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

type scopedKeyDataResponseSchema map[string]struct {
	Identifier           string `json:"identifier"`
	KeyRotationSecret    string `json:"keyRotationSecret"`
	KeyRotationTimestamp int64  `json:"keyRotationTimestamp"`
}
