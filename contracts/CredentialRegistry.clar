;; CredentialRegistry - Simple Credential Discovery System
;; Enables users to opt-in their credentials for discovery while maintaining privacy controls

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-CREDENTIAL-NOT-FOUND (err u401))
(define-constant ERR-ALREADY-REGISTERED (err u402))
(define-constant ERR-INVALID-VISIBILITY (err u403))

;; Registry for credentials - simplified
(define-map registered-credentials
    {owner: principal, credential-id: uint}
    {
        credential-type: (string-ascii 50),
        issuer-name: (string-ascii 100),
        visibility: (string-ascii 10),
        registered-at: uint,
        verified: bool
    }
)

;; Simple statistics tracking
(define-map credential-stats
    (string-ascii 50)
    {
        total-count: uint,
        public-count: uint
    }
)

;; Data variables
(define-data-var total-registered uint u0)

;; Register a credential in the discovery system
(define-public (register-credential 
    (credential-id uint)
    (credential-type (string-ascii 50))
    (issuer-name (string-ascii 100))
    (visibility (string-ascii 10)))
    (let (
        (sender tx-sender)
    )
        ;; Validate inputs
        (asserts! (or (is-eq visibility "public") (is-eq visibility "network") (is-eq visibility "private")) ERR-INVALID-VISIBILITY)
        (asserts! (is-none (map-get? registered-credentials {owner: sender, credential-id: credential-id})) ERR-ALREADY-REGISTERED)
        
        ;; Create registry entry
        (map-set registered-credentials
            {owner: sender, credential-id: credential-id}
            {
                credential-type: credential-type,
                issuer-name: issuer-name,
                visibility: visibility,
                registered-at: stacks-block-height,
                verified: false
            }
        )
        
        ;; Update statistics
        (update-stats credential-type (not (is-eq visibility "private")))
        
        ;; Update total counter
        (var-set total-registered (+ (var-get total-registered) u1))
        
        (ok true)
    )
)

;; Update credential visibility setting
(define-public (update-visibility (credential-id uint) (new-visibility (string-ascii 10)))
    (let (
        (sender tx-sender)
        (entry (unwrap! (map-get? registered-credentials {owner: sender, credential-id: credential-id}) ERR-CREDENTIAL-NOT-FOUND))
    )
        (asserts! (or (is-eq new-visibility "public") (is-eq new-visibility "network") (is-eq new-visibility "private")) ERR-INVALID-VISIBILITY)
        
        ;; Update entry
        (map-set registered-credentials
            {owner: sender, credential-id: credential-id}
            (merge entry {
                visibility: new-visibility
            })
        )
        
        (ok true)
    )
)

;; Update credential statistics - private helper
(define-private (update-stats (credential-type (string-ascii 50)) (is-public bool))
    (let (
        (current-stats (default-to {total-count: u0, public-count: u0} 
                                 (map-get? credential-stats credential-type)))
    )
        (map-set credential-stats
            credential-type
            {
                total-count: (+ (get total-count current-stats) u1),
                public-count: (if is-public (+ (get public-count current-stats) u1) (get public-count current-stats))
            }
        )
        true
    )
)

;; Read-only functions

;; Get credential by owner and ID
(define-read-only (get-credential (owner principal) (credential-id uint))
    (map-get? registered-credentials {owner: owner, credential-id: credential-id})
)

;; Get credential statistics
(define-read-only (get-credential-stats (credential-type (string-ascii 50)))
    (map-get? credential-stats credential-type)
)

;; Check if credential is registered
(define-read-only (is-credential-registered (owner principal) (credential-id uint))
    (is-some (map-get? registered-credentials {owner: owner, credential-id: credential-id}))
)

;; Get total registered count
(define-read-only (get-total-registered)
    (var-get total-registered)
)

;; Check if credential is publicly visible
(define-read-only (is-credential-visible (owner principal) (credential-id uint) (caller principal))
    (match (map-get? registered-credentials {owner: owner, credential-id: credential-id})
        entry (let (
            (visibility (get visibility entry))
        )
            (or 
                (is-eq visibility "public")
                (and (is-eq visibility "network") (not (is-eq caller owner)))
                (is-eq caller owner)
            )
        )
        false
    )
)

;; Get public credential info (respects privacy settings)
(define-read-only (get-public-credential (owner principal) (credential-id uint) (caller principal))
    (let (
        (entry (map-get? registered-credentials {owner: owner, credential-id: credential-id}))
    )
        (match entry
            credential (if (is-credential-visible owner credential-id caller)
                (some credential)
                none
            )
            none
        )
    )
)

;; Verify a credential exists and is active
(define-read-only (verify-credential (owner principal) (credential-id uint) (expected-type (string-ascii 50)))
    (match (map-get? registered-credentials {owner: owner, credential-id: credential-id})
        entry (and 
            (is-eq (get credential-type entry) expected-type)
            (get verified entry)
            (not (is-eq (get visibility entry) "private"))
        )
        false
    )
)

;; Simple search function - get all public credentials of a specific type
(define-read-only (search-credentials-by-type (credential-type (string-ascii 50)))
    (let (
        (stats (map-get? credential-stats credential-type))
    )
        (match stats
            stat-data (some {
                credential-type: credential-type,
                public-count: (get public-count stat-data),
                total-count: (get total-count stat-data)
            })
            none
        )
    )
)

;; Get registry summary for the ecosystem
(define-read-only (get-registry-summary)
    {
        total-registered: (var-get total-registered),
        contract-deployed: stacks-block-height
    }
)
