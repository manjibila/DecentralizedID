(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-NOT-REGISTERED (err u102))
(define-constant ERR-INVALID-CREDENTIAL (err u103))
(define-constant ERR-INVALID-SCORE (err u201))
(define-constant ERR-ALREADY-SCORED (err u202))
(define-constant ERR-REPUTATION-NOT-FOUND (err u203))

(define-map credential-reputation
    {credential-owner: principal, credential-id: uint}
    {
        trust-score: uint,
        verification-count: uint,
        endorsement-count: uint,
        challenge-count: uint,
        last-updated: uint,
        reputation-level: uint
    }
)

(define-map reputation-contributors
    {credential-owner: principal, credential-id: uint, contributor: principal}
    {
        score-given: uint,
        contribution-type: (string-ascii 20),
        timestamp: uint,
        weight: uint
    }
)

(define-map global-reputation
    principal
    {
        overall-score: uint,
        credential-count: uint,
        total-endorsements: uint,
        trust-level: uint,
        last-calculated: uint
    }
)

(define-map reputation-challenges
    {credential-owner: principal, credential-id: uint, challenger: principal}
    {
        challenge-type: (string-ascii 30),
        evidence: (string-ascii 200),
        status: (string-ascii 20),
        submitted-at: uint,
        resolved-at: uint,
        verdict: (string-ascii 20)
    }
)

(define-data-var reputation-decay-rate uint u5)
(define-data-var min-reputation-threshold uint u50)
(define-data-var max-reputation-score uint u1000)

(define-public (initialize-credential-reputation (credential-owner principal) (credential-id uint))
    (let (
        (sender tx-sender)
        (reputation-key {credential-owner: credential-owner, credential-id: credential-id})
    )
        (asserts! (is-eq sender credential-owner) ERR-NOT-AUTHORIZED)
        (asserts! (is-none (map-get? credential-reputation reputation-key)) ERR-ALREADY-SCORED)
        (ok (map-set credential-reputation
            reputation-key
            {
                trust-score: u100,
                verification-count: u0,
                endorsement-count: u0,
                challenge-count: u0,
                last-updated: stacks-block-height,
                reputation-level: u1
            }
        ))
    )
)

(define-public (contribute-reputation-score (credential-owner principal) (credential-id uint) (score uint) (contribution-type (string-ascii 20)))
    (let (
        (sender tx-sender)
        (reputation-key {credential-owner: credential-owner, credential-id: credential-id})
        (contribution-key {credential-owner: credential-owner, credential-id: credential-id, contributor: sender})
        (current-reputation (unwrap! (map-get? credential-reputation reputation-key) ERR-REPUTATION-NOT-FOUND))
    )
        (asserts! (not (is-eq sender credential-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (and (>= score u1) (<= score u100)) ERR-INVALID-SCORE)
        (asserts! (is-none (map-get? reputation-contributors contribution-key)) ERR-ALREADY-SCORED)
        (map-set reputation-contributors
            contribution-key
            {
                score-given: score,
                contribution-type: contribution-type,
                timestamp: stacks-block-height,
                weight: u10
            }
        )
        (let (
            (new-trust-score (calculate-new-trust-score 
                (get trust-score current-reputation) 
                score 
                (get verification-count current-reputation)
            ))
            (new-reputation-level (calculate-reputation-level new-trust-score))
        )
            (ok (map-set credential-reputation
                reputation-key
                (merge current-reputation {
                    trust-score: new-trust-score,
                    last-updated: stacks-block-height,
                    reputation-level: new-reputation-level
                })
            ))
        )
    )
)

(define-public (update-reputation-on-verification (credential-owner principal) (credential-id uint))
    (let (
        (sender tx-sender)
        (reputation-key {credential-owner: credential-owner, credential-id: credential-id})
        (current-reputation (unwrap! (map-get? credential-reputation reputation-key) ERR-REPUTATION-NOT-FOUND))
    )
        (let (
            (new-verification-count (+ (get verification-count current-reputation) u1))
            (verification-bonus (if (> new-verification-count u5) u20 u10))
            (new-trust-score (min-u (+ (get trust-score current-reputation) verification-bonus) (var-get max-reputation-score)))
            (new-reputation-level (calculate-reputation-level new-trust-score))
        )
            (ok (map-set credential-reputation
                reputation-key
                (merge current-reputation {
                    trust-score: new-trust-score,
                    verification-count: new-verification-count,
                    last-updated: stacks-block-height,
                    reputation-level: new-reputation-level
                })
            ))
        )
    )
)

(define-public (update-reputation-on-endorsement (credential-owner principal) (credential-id uint))
    (let (
        (sender tx-sender)
        (reputation-key {credential-owner: credential-owner, credential-id: credential-id})
        (current-reputation (unwrap! (map-get? credential-reputation reputation-key) ERR-REPUTATION-NOT-FOUND))
    )
        (let (
            (new-endorsement-count (+ (get endorsement-count current-reputation) u1))
            (endorsement-bonus u15)
            (new-trust-score (min-u (+ (get trust-score current-reputation) endorsement-bonus) (var-get max-reputation-score)))
            (new-reputation-level (calculate-reputation-level new-trust-score))
        )
            (ok (map-set credential-reputation
                reputation-key
                (merge current-reputation {
                    trust-score: new-trust-score,
                    endorsement-count: new-endorsement-count,
                    last-updated: stacks-block-height,
                    reputation-level: new-reputation-level
                })
            ))
        )
    )
)

(define-public (challenge-credential-reputation (credential-owner principal) (credential-id uint) (challenge-type (string-ascii 30)) (evidence (string-ascii 200)))
    (let (
        (sender tx-sender)
        (challenge-key {credential-owner: credential-owner, credential-id: credential-id, challenger: sender})
        (reputation-key {credential-owner: credential-owner, credential-id: credential-id})
        (current-reputation (unwrap! (map-get? credential-reputation reputation-key) ERR-REPUTATION-NOT-FOUND))
    )
        (asserts! (not (is-eq sender credential-owner)) ERR-NOT-AUTHORIZED)
        (map-set reputation-challenges
            challenge-key
            {
                challenge-type: challenge-type,
                evidence: evidence,
                status: "pending",
                submitted-at: stacks-block-height,
                resolved-at: u0,
                verdict: ""
            }
        )
        (let (
            (new-challenge-count (+ (get challenge-count current-reputation) u1))
            (challenge-penalty u10)
            (new-trust-score (if (> (get trust-score current-reputation) challenge-penalty) 
                (- (get trust-score current-reputation) challenge-penalty) 
                u0
            ))
            (new-reputation-level (calculate-reputation-level new-trust-score))
        )
            (ok (map-set credential-reputation
                reputation-key
                (merge current-reputation {
                    trust-score: new-trust-score,
                    challenge-count: new-challenge-count,
                    last-updated: stacks-block-height,
                    reputation-level: new-reputation-level
                })
            ))
        )
    )
)

(define-public (calculate-global-reputation (identity-owner principal))
    (let (
        (sender tx-sender)
        (current-global (default-to 
            {
                overall-score: u100,
                credential-count: u0,
                total-endorsements: u0,
                trust-level: u1,
                last-calculated: u0
            }
            (map-get? global-reputation identity-owner)
        ))
    )
        (asserts! (is-eq sender identity-owner) ERR-NOT-AUTHORIZED)
        (let (
            (base-score u100)
            (activity-bonus (* (get credential-count current-global) u5))
            (endorsement-bonus (* (get total-endorsements current-global) u3))
            (calculated-score (+ base-score activity-bonus endorsement-bonus))
            (final-score (min-u calculated-score (var-get max-reputation-score)))
            (trust-level (calculate-reputation-level final-score))
        )
            (ok (map-set global-reputation
                identity-owner
                {
                    overall-score: final-score,
                    credential-count: (get credential-count current-global),
                    total-endorsements: (get total-endorsements current-global),
                    trust-level: trust-level,
                    last-calculated: stacks-block-height
                }
            ))
        )
    )
)

(define-private (min-u (a uint) (b uint))
    (if (< a b) a b)
)

(define-private (calculate-new-trust-score (current-score uint) (new-score uint) (verification-count uint))
    (let (
        (weight-factor (if (> verification-count u0) (+ u10 verification-count) u10))
        (weighted-new-score (* new-score weight-factor))
        (weighted-current-score (* current-score weight-factor))
        (total-weight (* weight-factor u2))
        (calculated-score (/ (+ weighted-current-score weighted-new-score) total-weight))
    )
        (min-u calculated-score (var-get max-reputation-score))
    )
)

(define-private (calculate-reputation-level (trust-score uint))
    (if (>= trust-score u800)
        u5
        (if (>= trust-score u600)
            u4
            (if (>= trust-score u400)
                u3
                (if (>= trust-score u200)
                    u2
                    u1
                )
            )
        )
    )
)

(define-read-only (get-credential-reputation (credential-owner principal) (credential-id uint))
    (map-get? credential-reputation {credential-owner: credential-owner, credential-id: credential-id})
)

(define-read-only (get-global-reputation (identity-owner principal))
    (map-get? global-reputation identity-owner)
)

(define-read-only (get-reputation-contribution (credential-owner principal) (credential-id uint) (contributor principal))
    (map-get? reputation-contributors {credential-owner: credential-owner, credential-id: credential-id, contributor: contributor})
)

(define-read-only (get-reputation-challenge (credential-owner principal) (credential-id uint) (challenger principal))
    (map-get? reputation-challenges {credential-owner: credential-owner, credential-id: credential-id, challenger: challenger})
)

(define-read-only (is-reputable-credential (credential-owner principal) (credential-id uint))
    (match (map-get? credential-reputation {credential-owner: credential-owner, credential-id: credential-id})
        reputation-data (>= (get trust-score reputation-data) (var-get min-reputation-threshold))
        false
    )
)

(define-read-only (get-reputation-level-name (level uint))
    (if (is-eq level u5)
        "Expert"
        (if (is-eq level u4)
            "Advanced"
            (if (is-eq level u3)
                "Intermediate"
                (if (is-eq level u2)
                    "Basic"
                    "Novice"
                )
            )
        )
    )
)
