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



(define-map credential-ratings 
    {credential-id: uint, rater: principal}
    {
        rating: uint,
        timestamp: uint
    }
)

(define-public (rate-credential (credential-id uint) (rating uint))
    (let (
        (sender tx-sender)
        (credential (unwrap! (map-get? credentials {owner: sender, credential-id: credential-id}) ERR-INVALID-CREDENTIAL))
    )
        (asserts! (and (>= rating u1) (<= rating u5)) (err u104))
        (ok (map-set credential-ratings
            {credential-id: credential-id, rater: sender}
            {
                rating: rating,
                timestamp: stacks-block-height
            }
        ))
    )
)


(define-map recovery-addresses
    principal
    {
        backup: principal,
        activated: bool
    }
)

(define-public (set-recovery-address (backup-address principal))
    (let ((sender tx-sender))
        (asserts! (is-some (map-get? digital-identities sender)) ERR-NOT-REGISTERED)
        (ok (map-set recovery-addresses
            sender
            {
                backup: backup-address,
                activated: false
            }
        ))
    )
)

(define-public (recover-identity (original-address principal))
    (let (
        (sender tx-sender)
        (recovery-data (unwrap! (map-get? recovery-addresses original-address) ERR-NOT-AUTHORIZED))
    )
        (asserts! (and 
            (is-eq (get backup recovery-data) sender)
            (not (get activated recovery-data))
        ) ERR-NOT-AUTHORIZED)
        (ok (map-set recovery-addresses
            original-address
            (merge recovery-data {activated: true})
        ))
    )
)


(define-map credential-categories
    uint
    {
        name: (string-ascii 50),
        description: (string-ascii 100)
    }
)

(define-data-var next-category-id uint u1)

(define-public (create-credential-category (name (string-ascii 50)) (description (string-ascii 100)))
    (let ((category-id (var-get next-category-id)))
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (map-set credential-categories
            category-id
            {
                name: name,
                description: description
            }
        )
        (var-set next-category-id (+ category-id u1))
        (ok category-id)
    )
)


(define-map endorsements
    {credential-id: uint, endorser: principal}
    {
        message: (string-ascii 100),
        timestamp: uint
    }
)

(define-public (endorse-credential (credential-id uint) (message (string-ascii 100)))
    (let (
        (sender tx-sender)
        (credential (unwrap! (map-get? credentials {owner: sender, credential-id: credential-id}) ERR-INVALID-CREDENTIAL))
    )
        (ok (map-set endorsements
            {credential-id: credential-id, endorser: sender}
            {
                message: message,
                timestamp: stacks-block-height
            }
        ))
    )
)

(define-map scheduled-access
    {did-owner: principal, requestor: principal}
    {
        start-block: uint,
        end-block: uint,
        access-type: (string-ascii 10)
    }
)

(define-public (schedule-access (requestor principal) (duration uint) (access-type (string-ascii 10)))
    (let ((sender tx-sender))
        (asserts! (is-some (map-get? digital-identities sender)) ERR-NOT-REGISTERED)
        (ok (map-set scheduled-access
            {did-owner: sender, requestor: requestor}
            {
                start-block: stacks-block-height,
                end-block: (+ stacks-block-height duration),
                access-type: access-type
            }
        ))
    )
)


(define-map verification-levels
    principal
    {
        level: uint,
        last-updated: uint,
        verifier: principal
    }
)

(define-public (set-verification-level (identity-owner principal) (new-level uint))
    (let ((sender tx-sender))
        (asserts! (is-eq sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (is-some (map-get? digital-identities identity-owner)) ERR-NOT-REGISTERED)
        (ok (map-set verification-levels
            identity-owner
            {
                level: new-level,
                last-updated: stacks-block-height,
                verifier: sender
            }
        ))
    )
)


(define-map transfer-requests
    {credential-id: uint, from: principal, to: principal}
    {
        status: (string-ascii 20),
        requested-at: uint,
        processed-at: uint
    }
)

(define-public (request-credential-transfer (credential-id uint) (to principal))
    (let (
        (sender tx-sender)
        (credential (unwrap! (map-get? credentials {owner: sender, credential-id: credential-id}) ERR-INVALID-CREDENTIAL))
    )
        (ok (map-set transfer-requests
            {credential-id: credential-id, from: sender, to: to}
            {
                status: "pending",
                requested-at: stacks-block-height,
                processed-at: u0
            }
        ))
    )
)

(define-public (accept-credential-transfer (credential-id uint) (from principal))
    (let (
        (sender tx-sender)
        (transfer-request (unwrap! (map-get? transfer-requests {credential-id: credential-id, from: from, to: sender}) ERR-NOT-AUTHORIZED))
        (credential (unwrap! (map-get? credentials {owner: from, credential-id: credential-id}) ERR-INVALID-CREDENTIAL))
    )
        (map-set credentials
            {owner: sender, credential-id: credential-id}
            credential
        )
        (map-delete credentials {owner: from, credential-id: credential-id})
        (ok (map-set transfer-requests
            {credential-id: credential-id, from: from, to: sender}
            (merge transfer-request {
                status: "completed",
                processed-at: stacks-block-height
            })
        ))
    )
)


(define-public (reject-credential-transfer (credential-id uint) (from principal))
    (let (
        (sender tx-sender)
        (transfer-request (unwrap! (map-get? transfer-requests {credential-id: credential-id, from: from, to: sender}) ERR-NOT-AUTHORIZED))
    )
        (ok (map-set transfer-requests
            {credential-id: credential-id, from: from, to: sender}
            (merge transfer-request {
                status: "rejected",
                processed-at: stacks-block-height
            })
        ))
    )
)

(define-map expiration-notifications
    {owner: principal, credential-id: uint}
    {
        notification-sent: bool,
        notification-block: uint,
        days-before: uint
    }
)

(define-public (set-expiration-notification (credential-id uint) (days-before uint))
    (let (
        (sender tx-sender)
        (credential (unwrap! (map-get? credentials {owner: sender, credential-id: credential-id}) ERR-INVALID-CREDENTIAL))
    )
        (ok (map-set expiration-notifications
            {owner: sender, credential-id: credential-id}
            {
                notification-sent: false,
                notification-block: (- (get expiry-date credential) (* days-before u144)),
                days-before: days-before
            }
        ))
    )
)

