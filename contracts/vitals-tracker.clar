;; vitals-tracker
;; 
;; A contract that allows users to securely record and monitor essential health 
;; metrics, including heart rate, blood pressure, glucose levels, and other 
;; biometric data. The contract maintains a chronological history of measurements
;; for trend analysis and provides functions for calculating basic statistical insights.

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-VITAL-TYPE (err u101))
(define-constant ERR-INVALID-VALUE (err u102))
(define-constant ERR-NO-DATA-FOUND (err u103))
(define-constant ERR-FUTURE-TIMESTAMP (err u104))
(define-constant ERR-INVALID-TIMEFRAME (err u105))

;; Vital type constants
(define-constant VITAL-TYPE-HEART-RATE u1)
(define-constant VITAL-TYPE-BLOOD-PRESSURE-SYSTOLIC u2)
(define-constant VITAL-TYPE-BLOOD-PRESSURE-DIASTOLIC u3)
(define-constant VITAL-TYPE-GLUCOSE u4)
(define-constant VITAL-TYPE-WEIGHT u5)
(define-constant VITAL-TYPE-TEMPERATURE u6)
(define-constant VITAL-TYPE-OXYGEN-SATURATION u7)
(define-constant VITAL-TYPE-RESPIRATORY-RATE u8)

;; Data space definitions
;; Maps user address and timestamp to vital measurement records
(define-map vital-records 
  { user: principal, timestamp: uint, vital-type: uint } 
  { value: uint, notes: (optional (string-utf8 256)) }
)

;; Keeps track of the latest timestamp for each vital type per user
(define-map latest-vital-timestamp
  { user: principal, vital-type: uint }
  { timestamp: uint }
)

;; Tracks the number of measurements per vital type per user
(define-map vital-count
  { user: principal, vital-type: uint }
  { count: uint }
)

;; Private functions

;; Validates that the vital type is one of the supported types
(define-private (is-valid-vital-type (vital-type uint))
  (or
    (is-eq vital-type VITAL-TYPE-HEART-RATE)
    (is-eq vital-type VITAL-TYPE-BLOOD-PRESSURE-SYSTOLIC)
    (is-eq vital-type VITAL-TYPE-BLOOD-PRESSURE-DIASTOLIC)
    (is-eq vital-type VITAL-TYPE-GLUCOSE)
    (is-eq vital-type VITAL-TYPE-WEIGHT)
    (is-eq vital-type VITAL-TYPE-TEMPERATURE)
    (is-eq vital-type VITAL-TYPE-OXYGEN-SATURATION)
    (is-eq vital-type VITAL-TYPE-RESPIRATORY-RATE)
  )
)

;; Validates the value based on the vital type
(define-private (is-valid-value (vital-type uint) (value uint))
  (if (is-eq vital-type VITAL-TYPE-HEART-RATE)
      (and (>= value u30) (<= value u220)) ;; Heart rate typically between 30-220 bpm
    (if (is-eq vital-type VITAL-TYPE-BLOOD-PRESSURE-SYSTOLIC)
        (and (>= value u70) (<= value u250)) ;; Systolic BP typically between 70-250 mmHg
      (if (is-eq vital-type VITAL-TYPE-BLOOD-PRESSURE-DIASTOLIC)
          (and (>= value u40) (<= value u150)) ;; Diastolic BP typically between 40-150 mmHg
        (if (is-eq vital-type VITAL-TYPE-GLUCOSE)
            (and (>= value u20) (<= value u600)) ;; Glucose typically between 20-600 mg/dL
          (if (is-eq vital-type VITAL-TYPE-WEIGHT)
              (and (>= value u1000) (<= value u500000)) ;; Weight in grams (1kg-500kg)
            (if (is-eq vital-type VITAL-TYPE-TEMPERATURE)
                (and (>= value u340) (<= value u430)) ;; Temperature in tenths of Celsius (34.0C-43.0C)
              (if (is-eq vital-type VITAL-TYPE-OXYGEN-SATURATION)
                  (and (>= value u50) (<= value u100)) ;; SpO2 typically between 50-100%
                (if (is-eq vital-type VITAL-TYPE-RESPIRATORY-RATE)
                    (and (>= value u4) (<= value u60)) ;; Respiratory rate typically between 4-60 breaths/min
                  false
                )
              )
            )
          )
        )
      )
    )
  )
)

;; Updates the latest timestamp for a user's vital type
(define-private (update-latest-timestamp (user principal) (vital-type uint) (timestamp uint))
  (map-set latest-vital-timestamp 
    { user: user, vital-type: vital-type }
    { timestamp: timestamp }
  )
)

;; Increments the count of measurements for a user's vital type
(define-private (increment-vital-count (user principal) (vital-type uint))
  (let (
    (current-count (default-to u0 (get count (map-get? vital-count { user: user, vital-type: vital-type }))))
  )
    (map-set vital-count
      { user: user, vital-type: vital-type }
      { count: (+ current-count u1) }
    )
  )
)

;; Read-only functions

;; Get a specific vital record
(define-read-only (get-vital-record (user principal) (timestamp uint) (vital-type uint))
  (map-get? vital-records { user: user, timestamp: timestamp, vital-type: vital-type })
)

;; Get the latest vital measurement for a specific vital type
(define-read-only (get-latest-vital (user principal) (vital-type uint))
  (let (
    (latest-timestamp (get timestamp (default-to { timestamp: u0 } 
                         (map-get? latest-vital-timestamp { user: user, vital-type: vital-type }))))
  )
    (if (is-eq latest-timestamp u0)
        (ok none)
        (ok (map-get? vital-records { user: user, timestamp: latest-timestamp, vital-type: vital-type }))
    )
  )
)

;; Get the count of measurements for a specific vital type
(define-read-only (get-vital-count (user principal) (vital-type uint))
  (default-to { count: u0 } (map-get? vital-count { user: user, vital-type: vital-type }))
)

;; Check if a vital type is valid
(define-read-only (check-vital-type-validity (vital-type uint))
  (ok (is-valid-vital-type vital-type))
)

;; Check if a value is valid for a specific vital type
(define-read-only (check-value-validity (vital-type uint) (value uint))
  (ok (is-valid-value vital-type value))
)

;; Public functions

;; Record a new vital measurement
(define-public (record-vital (vital-type uint) (value uint) (timestamp uint) (notes (optional (string-utf8 256))))
  (let (
    (user tx-sender)
    (current-time (unwrap! (get-block-info? time (- block-height u1)) (err u500)))
  )
    ;; Validate inputs
    (asserts! (is-valid-vital-type vital-type) ERR-INVALID-VITAL-TYPE)
    (asserts! (is-valid-value vital-type value) ERR-INVALID-VALUE)
    (asserts! (<= timestamp current-time) ERR-FUTURE-TIMESTAMP)
    
    ;; Store the vital record
    (map-set vital-records
      { user: user, timestamp: timestamp, vital-type: vital-type }
      { value: value, notes: notes }
    )
    
    ;; Update metadata
    (update-latest-timestamp user vital-type timestamp)
    (increment-vital-count user vital-type)
    
    (ok true)
  )
)

;; Update an existing vital measurement (only the owner can update)
(define-public (update-vital (timestamp uint) (vital-type uint) (value uint) (notes (optional (string-utf8 256))))
  (let (
    (user tx-sender)
    (existing-record (map-get? vital-records { user: user, timestamp: timestamp, vital-type: vital-type }))
  )
    ;; Validate inputs and state
    (asserts! (is-valid-vital-type vital-type) ERR-INVALID-VITAL-TYPE)
    (asserts! (is-valid-value vital-type value) ERR-INVALID-VALUE)
    (asserts! (is-some existing-record) ERR-NO-DATA-FOUND)
    
    ;; Update the record
    (map-set vital-records
      { user: user, timestamp: timestamp, vital-type: vital-type }
      { value: value, notes: notes }
    )
    
    (ok true)
  )
)

;; Delete a vital measurement
(define-public (delete-vital (timestamp uint) (vital-type uint))
  (let (
    (user tx-sender)
    (existing-record (map-get? vital-records { user: user, timestamp: timestamp, vital-type: vital-type }))
    (current-count (get count (default-to { count: u0 } (map-get? vital-count { user: user, vital-type: vital-type }))))
  )
    ;; Validate state
    (asserts! (is-some existing-record) ERR-NO-DATA-FOUND)
    
    ;; Delete the record
    (map-delete vital-records { user: user, timestamp: timestamp, vital-type: vital-type })
    
    ;; Update count
    (map-set vital-count
      { user: user, vital-type: vital-type }
      { count: (- current-count u1) }
    )
    
    ;; Update latest timestamp if needed
    (let (
      (latest-timestamp (get timestamp (default-to { timestamp: u0 } 
                           (map-get? latest-vital-timestamp { user: user, vital-type: vital-type }))))
    )
      (if (is-eq timestamp latest-timestamp)
          ;; We need to find the new latest timestamp
          ;; This is simplified and would require a more complex implementation
          ;; in a real application to find the new max timestamp
          (map-delete latest-vital-timestamp { user: user, vital-type: vital-type })
          true
      )
    )
    
    (ok true)
  )
)

;; Share vital data with another user or contract
(define-public (share-vital-with (recipient principal) (vital-type uint) (timestamp uint))
  (let (
    (user tx-sender)
    (vital-data (map-get? vital-records { user: user, timestamp: timestamp, vital-type: vital-type }))
  )
    (asserts! (is-some vital-data) ERR-NO-DATA-FOUND)
    
    ;; In a real implementation, this would use a more sophisticated
    ;; permission system, potentially with a data-sharing map
    (ok vital-data)
  )
)