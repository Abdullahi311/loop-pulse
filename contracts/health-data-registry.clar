;; health-data-registry
;; 
;; A central registry for the Loop Pulse health monitoring platform that enables
;; users to register and manage permissions for their health data. This contract
;; implements fine-grained access controls allowing users to grant specific
;; permissions to healthcare providers or applications.

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-USER-ALREADY-REGISTERED (err u101))
(define-constant ERR-USER-NOT-REGISTERED (err u102))
(define-constant ERR-INVALID-DATA-CATEGORY (err u103))
(define-constant ERR-ALREADY-GRANTED (err u104))
(define-constant ERR-NO-PERMISSION-FOUND (err u105))

;; Data Categories
(define-constant DATA-CATEGORY-VITALS u1)
(define-constant DATA-CATEGORY-LAB-RESULTS u2)
(define-constant DATA-CATEGORY-MEDICATIONS u3)
(define-constant DATA-CATEGORY-MEDICAL-HISTORY u4)

;; Permission Types
(define-constant PERMISSION-READ u1)
(define-constant PERMISSION-WRITE u2)
(define-constant PERMISSION-FULL u3)

;; Data Maps

;; Stores user registration status
(define-map users 
  { user: principal }
  { registered: bool, registration-time: uint }
)

;; Maps users to their data categories and locations
(define-map user-data-references
  { user: principal, category: uint }
  { data-contract: principal, reference-id: (optional (string-utf8 64)) }
)

;; Stores access permissions for each user's data
(define-map data-permissions
  { owner: principal, category: uint, accessor: principal }
  { permission-type: uint, granted-at: uint, expiration: (optional uint) }
)

;; Private Functions

;; Checks if a user is registered
(define-private (is-user-registered (user principal))
  (default-to false (get registered (map-get? users { user: user })))
)

;; Checks if a permission exists and is valid
(define-private (is-permission-valid (owner principal) (category uint) (accessor principal) (required-permission uint))
  (let ((permission (map-get? data-permissions { owner: owner, category: category, accessor: accessor })))
    (if (is-none permission)
      false
      (let ((permission-details (unwrap-panic permission)))
        (and
          ;; Check permission level is sufficient
          (or 
            (is-eq (get permission-type permission-details) required-permission)
            (is-eq (get permission-type permission-details) PERMISSION-FULL)
          )
          ;; Check expiration if it exists
          (match (get expiration permission-details)
            expiry-time (> expiry-time block-height)
            true  ;; No expiration time set
          )
        )
      )
    )
  )
)

;; Validates data category
(define-private (is-valid-data-category (category uint))
  (or
    (is-eq category DATA-CATEGORY-VITALS)
    (is-eq category DATA-CATEGORY-LAB-RESULTS)
    (is-eq category DATA-CATEGORY-MEDICATIONS)
    (is-eq category DATA-CATEGORY-MEDICAL-HISTORY)
  )
)

;; Validates permission type
(define-private (is-valid-permission-type (permission-type uint))
  (or
    (is-eq permission-type PERMISSION-READ)
    (is-eq permission-type PERMISSION-WRITE)
    (is-eq permission-type PERMISSION-FULL)
  )
)

;; Read-only Functions

;; Check if a user is registered
(define-read-only (user-registered (user principal))
  (is-user-registered user)
)

;; Get data reference for a specific category
(define-read-only (get-data-reference (user principal) (category uint))
  (if (and
        (is-user-registered user)
        (is-valid-data-category category)
      )
    (ok (map-get? user-data-references { user: user, category: category }))
    (err (if (not (is-user-registered user))
          ERR-USER-NOT-REGISTERED
          ERR-INVALID-DATA-CATEGORY))
  )
)

;; Check if accessor has permission for user's data
(define-read-only (has-permission (owner principal) (category uint) (accessor principal) (required-permission uint))
  (if (and
        (is-user-registered owner)
        (is-valid-data-category category)
        (is-valid-permission-type required-permission)
      )
    (ok (is-permission-valid owner category accessor required-permission))
    (err (if (not (is-user-registered owner))
          ERR-USER-NOT-REGISTERED
          ERR-INVALID-DATA-CATEGORY))
  )
)

;; Get a list of all permissions for a specific data category
(define-read-only (get-permissions-for-category (owner principal) (category uint))
  (if (and
        (is-user-registered owner)
        (is-valid-data-category category)
      )
    (ok (map-get? data-permissions { owner: owner, category: category, accessor: tx-sender }))
    (err (if (not (is-user-registered owner))
          ERR-USER-NOT-REGISTERED
          ERR-INVALID-DATA-CATEGORY))
  )
)

;; Public Functions

;; Register as a new user
(define-public (register-user)
  (let ((user tx-sender))
    (if (is-user-registered user)
      ERR-USER-ALREADY-REGISTERED
      (begin
        (map-set users 
          { user: user }
          { registered: true, registration-time: block-height }
        )
        (ok true)
      )
    )
  )
)

;; Update data reference for a specific category
(define-public (set-data-reference (category uint) (data-contract principal) (reference-id (optional (string-utf8 64))))
  (let ((user tx-sender))
    (if (and
          (is-user-registered user)
          (is-valid-data-category category)
        )
      (begin
        (map-set user-data-references
          { user: user, category: category }
          { data-contract: data-contract, reference-id: reference-id }
        )
        (ok true)
      )
      (err (if (not (is-user-registered user))
            ERR-USER-NOT-REGISTERED
            ERR-INVALID-DATA-CATEGORY))
    )
  )
)

;; Grant permission to an accessor for a data category
(define-public (grant-permission 
    (category uint) 
    (accessor principal) 
    (permission-type uint) 
    (expiration (optional uint))
  )
  (let ((owner tx-sender))
    (if (and
          (is-user-registered owner)
          (is-valid-data-category category)
          (is-valid-permission-type permission-type)
        )
      (begin
        (map-set data-permissions
          { owner: owner, category: category, accessor: accessor }
          { permission-type: permission-type, granted-at: block-height, expiration: expiration }
        )
        (ok true)
      )
      (err (if (not (is-user-registered owner))
            ERR-USER-NOT-REGISTERED
            ERR-INVALID-DATA-CATEGORY))
    )
  )
)

;; Revoke permission for a data category
(define-public (revoke-permission (category uint) (accessor principal))
  (let ((owner tx-sender))
    (if (and
          (is-user-registered owner)
          (is-valid-data-category category)
        )
      (if (map-delete data-permissions { owner: owner, category: category, accessor: accessor })
        (ok true)
        ERR-NO-PERMISSION-FOUND
      )
      (err (if (not (is-user-registered owner))
            ERR-USER-NOT-REGISTERED
            ERR-INVALID-DATA-CATEGORY))
    )
  )
)

;; Update an existing permission
(define-public (update-permission
    (category uint)
    (accessor principal)
    (permission-type uint)
    (expiration (optional uint))
  )
  (let ((owner tx-sender))
    (if (and
          (is-user-registered owner)
          (is-valid-data-category category)
          (is-valid-permission-type permission-type)
          (map-get? data-permissions { owner: owner, category: category, accessor: accessor })
        )
      (begin
        (map-set data-permissions
          { owner: owner, category: category, accessor: accessor }
          { permission-type: permission-type, granted-at: block-height, expiration: expiration }
        )
        (ok true)
      )
      (err (if (not (is-user-registered owner))
            ERR-USER-NOT-REGISTERED
            (if (not (is-valid-data-category category))
              ERR-INVALID-DATA-CATEGORY
              ERR-NO-PERMISSION-FOUND)))
    )
  )
)