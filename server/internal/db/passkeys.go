package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// 通行证(WebAuthn)登录。威胁模型见 internal/handlers/passkey.go 顶部注释。
//
// 这里只管存取。两条不变量由查询本身保证,而不是靠调用方记得检查:
//   - 只认 key_fp 等于当前访问密钥指纹的通行证 / 会话(换了密钥一律失效)
//   - 会话必须没过期,且它的通行证还在(删通行证即吊销)

// Passkey 一条已注册的通行证
type Passkey struct {
	ID           int64
	CredentialID string // base64url
	Name         string
	RPID         string
	Credential   string // webauthn.Credential JSON
	KeyFP        string
	CreatedAt    time.Time
	LastUsed     sql.NullTime
}

// WebSessionTTL 通行证登录会话的有效期
const WebSessionTTL = 30 * 24 * time.Hour

var ErrPasskeyNotFound = errors.New("通行证不存在")

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// AddPasskey 保存新注册的通行证
func (d *DB) AddPasskey(p Passkey) (int64, error) {
	res, err := d.Exec(
		`INSERT INTO passkeys(credential_id, name, rp_id, credential, key_fp, created_at) VALUES(?,?,?,?,?,?)`,
		p.CredentialID, p.Name, p.RPID, p.Credential, p.KeyFP, nowRFC3339())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func scanPasskeys(rows *sql.Rows) ([]Passkey, error) {
	defer rows.Close()
	out := []Passkey{}
	for rows.Next() {
		var p Passkey
		var created string
		var last sql.NullString
		if err := rows.Scan(&p.ID, &p.CredentialID, &p.Name, &p.RPID, &p.Credential, &p.KeyFP, &created, &last); err != nil {
			return nil, err
		}
		p.CreatedAt, _ = time.Parse(time.RFC3339, created)
		p.LastUsed = scanDeviceTime(last)
		out = append(out, p)
	}
	return out, rows.Err()
}

const passkeyCols = `id, credential_id, name, rp_id, credential, key_fp, created_at, last_used`

// ListPasskeys 全部通行证(含已因换密钥失效的,管理界面要能看到并删掉)
func (d *DB) ListPasskeys() ([]Passkey, error) {
	rows, err := d.Query(`SELECT ` + passkeyCols + ` FROM passkeys ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	return scanPasskeys(rows)
}

// ActivePasskeys 当前密钥下、某个 RP(域名)的有效通行证
func (d *DB) ActivePasskeys(rpID, keyFP string) ([]Passkey, error) {
	rows, err := d.Query(`SELECT `+passkeyCols+` FROM passkeys WHERE rp_id = ? AND key_fp = ? ORDER BY id`, rpID, keyFP)
	if err != nil {
		return nil, err
	}
	return scanPasskeys(rows)
}

// UpdatePasskeyAfterLogin 登录成功后写回签名计数器 / 标志位,刷新最近使用时间
func (d *DB) UpdatePasskeyAfterLogin(id int64, credentialJSON string) error {
	_, err := d.Exec(`UPDATE passkeys SET credential = ?, last_used = ? WHERE id = ?`, credentialJSON, nowRFC3339(), id)
	return err
}

// DeletePasskey 删除通行证,并吊销用它登录出来的全部会话
func (d *DB) DeletePasskey(id int64) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM passkeys WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrPasskeyNotFound
	}
	if _, err := tx.Exec(`DELETE FROM web_sessions WHERE passkey_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateWebSession 通行证登录成功后发会话令牌。令牌只返回这一次,库里只存摘要
func (d *DB) CreateWebSession(passkeyID int64, keyFP, ip, userAgent string) (token string, expires time.Time, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token = hex.EncodeToString(raw)
	if len(userAgent) > 200 {
		userAgent = userAgent[:200]
	}
	expires = time.Now().Add(WebSessionTTL).UTC()
	// 顺手清掉过期的,表不会无限长
	_, _ = d.Exec(`DELETE FROM web_sessions WHERE expires_at < ?`, nowRFC3339())
	_, err = d.Exec(
		`INSERT INTO web_sessions(token_hash, passkey_id, key_fp, created_at, expires_at, ip, user_agent) VALUES(?,?,?,?,?,?,?)`,
		hashToken(token), passkeyID, keyFP, nowRFC3339(), expires.Format(time.RFC3339), ip, userAgent)
	return token, expires, err
}

// WebSessionValid 会话令牌是否有效:没过期、密钥没换、通行证还在。命中时节流刷新 last_used
func (d *DB) WebSessionValid(token, keyFP string) (sessionID int64, ok bool) {
	var last sql.NullString
	err := d.QueryRow(
		`SELECT s.id, s.last_used FROM web_sessions s JOIN passkeys p ON p.id = s.passkey_id
		 WHERE s.token_hash = ? AND s.key_fp = ? AND p.key_fp = ? AND s.expires_at > ?`,
		hashToken(token), keyFP, keyFP, nowRFC3339()).Scan(&sessionID, &last)
	if err != nil {
		return 0, false
	}
	refresh := !last.Valid
	if last.Valid {
		if t, perr := time.Parse(time.RFC3339, last.String); perr != nil || time.Since(t) > 5*time.Minute {
			refresh = true
		}
	}
	if refresh {
		_, _ = d.Exec(`UPDATE web_sessions SET last_used = ? WHERE id = ?`, nowRFC3339(), sessionID)
	}
	return sessionID, true
}

// RevokeWebSession 退出登录
func (d *DB) RevokeWebSession(token string) error {
	_, err := d.Exec(`DELETE FROM web_sessions WHERE token_hash = ?`, hashToken(token))
	return err
}

// CountWebSessions 某个通行证名下还有效的会话数(管理界面展示用)
func (d *DB) CountWebSessions(passkeyID int64) int {
	var n int
	_ = d.QueryRow(`SELECT COUNT(*) FROM web_sessions WHERE passkey_id = ? AND expires_at > ?`, passkeyID, nowRFC3339()).Scan(&n)
	return n
}
