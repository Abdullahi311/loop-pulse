;; provider-authorization
;; 
;; This contract manages healthcare provider identities and authorized access to patient health data
;; in the Loop Pulse health monitoring platform. It creates a secure framework to verify providers,
;; track patient-granted permissions, and enforce time-bound access controls, ensuring patients
;; maintain control over their health data while enabling necessary medical care.

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u1001))
(define-constant ERR-UNKNOWN-PROVIDER (err u1002))
(define-constant ERR-ALREADY-REGISTERED (err u1003))
(define-constant ERR-INVALID-REQUEST (err u1004))
(define-constant ERR-NO-ACCESS-GRANTED (err u1005))
(define-constant ERR-ACCESS-EXPIRED (err u1006))
(define-constant ERR-SELF-AUTHORIZATION (err u1007))
(define-constant ERR-ALREADY-AUTHORIZED (err u1008))
(define-constant ERR-NOT-ADMIN (err u1009))

;; Data structures

;; Map of registered healthcare providers
;; The value is a tuple containing provider metadata
(define-map providers
  { provider-id: principal }
  {
    name: (string-utf8 100),
    specialty: (string-utf8 100),
    license-id: (string-utf8 50),
    verified: bool,
    registration-time: uint
  }
)

;; Map tracking provider access to patient data
;; Keys are composite of patient and provider principals
(define-map access-grants
  { patient: principal, provider: principal }
  {
    granted-at: uint,
    expires-at: uint,
    access-level: (string-utf8 20), ;; "basic", "full", "emergency"
    data-types: (list 10 (string-utf8 30)) ;; specific data types accessible
  }
)

;; Map of pending access requests from providers to patients
(define-map access-requests
  { patient: principal, provider: principal, request-id: uint }
  {
    requested-at: uint,
    requested-duration: uint, ;; in seconds
    access-level: (string-utf8 20),
    data-types: (list 10 (string-utf8 30)),
    message: (string-utf8 200)
  }
)

;; Track the next request ID to ensure uniqueness
(define-data-var next-request-id uint u1)

;; Contract admin
(define-data-var contract-admin principal tx-sender)

;; Private functions

;; Check if caller is the contract administrator
(define-private (is-admin)
  (is-eq tx-sender (var-get contract-admin))
)

;; Check if a provider exists and is verified
(define-private (is-verified-provider (provider-id principal))
  (match (map-get? providers { provider-id: provider-id })
    provider-info (get verified provider-info)
    false
  )
)

;; Check if a provider has active access to a patient's data
(define-private (has-active-access (patient principal) (provider principal))
  (match (map-get? access-grants { patient: patient, provider: provider })
    grant-info (> (get expires-at grant-info) block-height)
    false
  )
)

;; Generate a new unique request ID
(define-private (get-next-request-id)
  (let ((current-id (var-get next-request-id)))
    (var-set next-request-id (+ current-id u1))
    current-id
  )
)

;; Read-only functions

;; Get provider information if registered
(define-read-only (get-provider-info (provider-id principal))
  (match (map-get? providers { provider-id: provider-id })
    provider-info (ok provider-info)
    ERR-UNKNOWN-PROVIDER
  )
)

;; Check if a provider is registered and verified
(define-read-only (is-provider-verified (provider-id principal))
  (ok (is-verified-provider provider-id))
)

;; Get the current access status between a patient and provider
(define-read-only (get-access-status (patient principal) (provider principal))
  (match (map-get? access-grants { patient: patient, provider: provider })
    grant-info 
    (let ((is-active (> (get expires-at grant-info) block-height)))
      (ok {
        has-access: is-active,
        access-details: grant-info,
        access-expired: (not is-active)
      })
    )
    (ok {
      has-access: false,
      access-details: none,
      access-expired: false
    })
  )
)

;; Get all pending access requests for a patient
(define-read-only (get-pending-requests (patient principal))
  (ok (map-get? access-requests { patient: patient, provider: tx-sender, request-id: (get-next-request-id) }))
)

;; Public functions

;; Set a new contract administrator
(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin) ERR-NOT-AUTHORIZED)
    (var-set contract-admin new-admin)
    (ok true)
  )
)

;; Register a new healthcare provider
(define-public (register-provider (name (string-utf8 100)) (specialty (string-utf8 100)) (license-id (string-utf8 50)))
  (let ((provider-id tx-sender))
    (asserts! (is-none (map-get? providers { provider-id: provider-id })) ERR-ALREADY-REGISTERED)
    
    (map-set providers
      { provider-id: provider-id }
      {
        name: name,
        specialty: specialty,
        license-id: license-id,
        verified: false,
        registration-time: block-height
      }
    )
    (ok true)
  )
)

;; Verify a provider (admin only)
(define-public (verify-provider (provider-id principal))
  (begin
    (asserts! (is-admin) ERR-NOT-ADMIN)
    
    (match (map-get? providers { provider-id: provider-id })
      provider-info
      (begin
        (map-set providers
          { provider-id: provider-id }
          (merge provider-info { verified: true })
        )
        (ok true)
      )
      ERR-UNKNOWN-PROVIDER
    )
  )
)

;; Provider requests access to patient data
(define-public (request-access 
    (patient principal) 
    (duration uint) 
    (access-level (string-utf8 20)) 
    (data-types (list 10 (string-utf8 30)))
    (message (string-utf8 200))
  )
  (let (
    (provider-id tx-sender)
    (request-id (get-next-request-id))
  )
    ;; Validate input
    (asserts! (not (is-eq patient provider-id)) ERR-SELF-AUTHORIZATION)
    (asserts! (is-verified-provider provider-id) ERR-UNKNOWN-PROVIDER)
    (asserts! (> duration u0) ERR-INVALID-REQUEST)
    
    ;; Create the access request
    (map-set access-requests
      { patient: patient, provider: provider-id, request-id: request-id }
      {
        requested-at: block-height,
        requested-duration: duration,
        access-level: access-level,
        data-types: data-types,
        message: message
      }
    )
    (ok request-id)
  )
)

;; Patient grants access to a provider
(define-public (grant-access 
    (provider principal) 
    (duration uint) 
    (access-level (string-utf8 20)) 
    (data-types (list 10 (string-utf8 30)))
  )
  (let (
    (patient tx-sender)
    (expires-at (+ block-height duration))
  )
    ;; Validate input
    (asserts! (not (is-eq patient provider)) ERR-SELF-AUTHORIZATION)
    (asserts! (is-verified-provider provider) ERR-UNKNOWN-PROVIDER)
    (asserts! (> duration u0) ERR-INVALID-REQUEST)
    
    ;; Grant access
    (map-set access-grants
      { patient: patient, provider: provider }
      {
        granted-at: block-height,
        expires-at: expires-at,
        access-level: access-level,
        data-types: data-types
      }
    )
    (ok expires-at)
  )
)

;; Approve a specific access request
(define-public (approve-request (provider principal) (request-id uint))
  (let (
    (patient tx-sender)
  )
    (match (map-get? access-requests { patient: patient, provider: provider, request-id: request-id })
      request-info
      (begin
        ;; Grant the requested access
        (map-set access-grants
          { patient: patient, provider: provider }
          {
            granted-at: block-height,
            expires-at: (+ block-height (get requested-duration request-info)),
            access-level: (get access-level request-info),
            data-types: (get data-types request-info)
          }
        )
        ;; Delete the request since it's approved
        (map-delete access-requests { patient: patient, provider: provider, request-id: request-id })
        (ok true)
      )
      ERR-INVALID-REQUEST
    )
  )
)

;; Patient revokes a provider's access
(define-public (revoke-access (provider principal))
  (let (
    (patient tx-sender)
  )
    (asserts! (has-active-access patient provider) ERR-NO-ACCESS-GRANTED)
    
    ;; Delete the access grant
    (map-delete access-grants { patient: patient, provider: provider })
    (ok true)
  )
)

;; Provider checks if they can access specific patient data
(define-public (check-data-access (patient principal) (data-type (string-utf8 30)))
  (let ((provider tx-sender))
    (match (map-get? access-grants { patient: patient, provider: provider })
      grant-info
      (let (
        (is-active (> (get expires-at grant-info) block-height))
        (authorized-types (get data-types grant-info))
      )
        (if (and is-active (default-to false (index-of authorized-types data-type)))
          (ok true)
          (if (not is-active) 
            ERR-ACCESS-EXPIRED
            ERR-NO-ACCESS-GRANTED
          )
        )
      )
      ERR-NO-ACCESS-GRANTED
    )
  )
)

;; Extend an existing access grant's duration
(define-public (extend-access (provider principal) (additional-duration uint))
  (let (
    (patient tx-sender)
  )
    (match (map-get? access-grants { patient: patient, provider: provider })
      grant-info
      (begin
        ;; Extend the duration
        (map-set access-grants
          { patient: patient, provider: provider }
          (merge grant-info { expires-at: (+ (get expires-at grant-info) additional-duration) })
        )
        (ok true)
      )
      ERR-NO-ACCESS-GRANTED
    )
  )
)