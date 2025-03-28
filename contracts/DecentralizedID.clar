;; DecentralizedID - Self-sovereign identity platform
;; Allows users to manage their digital identity and credentials with privacy controls

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-REGISTERED (err u101))
(define-constant ERR-NOT-REGISTERED (err u102))
(define-constant ERR-INVALID-CREDENTIAL (err u103))

;; Data Maps
(define-map digital-identities 
    principal 
    {
        did-string: (string-ascii 50),
        active: bool,
        registration-date: uint,
        privacy-level: uint
    }
)

(define-map credentials 
    {owner: principal, credential-id: uint} 
    {
        credential-type: (string-ascii 50),
        issuer: principal,
        issue-date: uint,
        expiry-date: uint,
        revoked: bool,
        metadata: (string-ascii 256)
    }
)

(define-map access-controls
    {did-owner: principal, requestor: principal}
    {
        can-view-credentials: bool,
        can-view-profile: bool,
        access-expiry: uint
    }
)

;; Data Variables
(define-data-var next-credential-id uint u1)

;; Public Functions

;; Register new digital identity
(define-public (register-identity (did-string (string-ascii 50)))
    (let ((sender tx-sender))
        (asserts! (is-none (map-get? digital-identities sender)) ERR-ALREADY-REGISTERED)
        (ok (map-set digital-identities 
            sender
            {
                did-string: did-string,
                active: true,
                registration-date: stacks-block-height,
                privacy-level: u1
            }
        ))
    )
)

;; Add new credential
(define-public (add-credential 
        (credential-type (string-ascii 50))
        (expiry-date uint)
        (metadata (string-ascii 256)))
    (let (
        (credential-id (var-get next-credential-id))
        (sender tx-sender)
    )
        (asserts! (is-some (map-get? digital-identities sender)) ERR-NOT-REGISTERED)
        (map-set credentials
            {owner: sender, credential-id: credential-id}
            {
                credential-type: credential-type,
                issuer: sender,
                issue-date: stacks-block-height,
                expiry-date: expiry-date,
                revoked: false,
                metadata: metadata
            }
        )
        (var-set next-credential-id (+ credential-id u1))
        (ok credential-id)
    )
)

;; Grant access to another principal
(define-public (grant-access (requestor principal) (view-credentials bool) (view-profile bool) (access-duration uint))
    (let ((sender tx-sender))
        (asserts! (is-some (map-get? digital-identities sender)) ERR-NOT-REGISTERED)
        (ok (map-set access-controls
            {did-owner: sender, requestor: requestor}
            {
                can-view-credentials: view-credentials,
                can-view-profile: view-profile,
                access-expiry: (+ stacks-block-height access-duration)
            }
        ))
    )
)

;; Revoke access
(define-public (revoke-access (requestor principal))
    (let ((sender tx-sender))
        (ok (map-delete access-controls {did-owner: sender, requestor: requestor}))
    )
)

;; Update privacy level
(define-public (set-privacy-level (new-level uint))
    (let ((sender tx-sender)
          (identity (unwrap! (map-get? digital-identities sender) ERR-NOT-REGISTERED)))
        (ok (map-set digital-identities
            sender
            (merge identity {privacy-level: new-level})
        ))
    )
)

;; Revoke credential
(define-public (revoke-credential (credential-id uint))
    (let (
        (sender tx-sender)
        (credential (unwrap! (map-get? credentials {owner: sender, credential-id: credential-id}) ERR-INVALID-CREDENTIAL))
    )
        (ok (map-set credentials
            {owner: sender, credential-id: credential-id}
            (merge credential {revoked: true})
        ))
    )
)

;; Read-only Functions

;; Check if principal has access to view credentials
(define-read-only (has-credential-access (did-owner principal) (requestor principal))
    (match (map-get? access-controls {did-owner: did-owner, requestor: requestor})
        access-data (and 
            (get can-view-credentials access-data)
            (< stacks-block-height (get access-expiry access-data))
        )
        false
    )
)

;; Get identity information
(define-read-only (get-identity (identity-owner principal))
    (map-get? digital-identities identity-owner)
)

;; Get credential information
(define-read-only (get-credential (owner principal) (credential-id uint))
    (map-get? credentials {owner: owner, credential-id: credential-id})
)

;; Check if identity is registered
(define-read-only (is-registered (identity-owner principal))
    (is-some (map-get? digital-identities identity-owner))
)
