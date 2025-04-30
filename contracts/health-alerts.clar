;; health-alerts contract
;; This contract enables proactive health monitoring through personalized health alerts
;; Users can define thresholds for various health metrics, and the system generates
;; alerts when recorded values exceed these thresholds.

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u1001))
(define-constant ERR-ALERT-NOT-FOUND (err u1002))
(define-constant ERR-INVALID-THRESHOLD (err u1003))
(define-constant ERR-INVALID-METRIC-TYPE (err u1004))
(define-constant ERR-NO-DATA-AVAILABLE (err u1005))
(define-constant ERR-RECIPIENT-NOT-FOUND (err u1006))
(define-constant ERR-ALREADY-EXISTS (err u1007))

;; Supported health metric types
(define-constant METRIC-HEART-RATE u1)
(define-constant METRIC-BLOOD-PRESSURE u2)
(define-constant METRIC-BLOOD-GLUCOSE u3)
(define-constant METRIC-TEMPERATURE u4)
(define-constant METRIC-OXYGEN-SATURATION u5)

;; Alert severity levels
(define-constant SEVERITY-LOW u1)
(define-constant SEVERITY-MEDIUM u2)
(define-constant SEVERITY-HIGH u3)

;; Data maps and variables

;; Stores user-defined alert thresholds for health metrics
(define-map alert-thresholds
  { user: principal, metric-type: uint, alert-id: uint }
  { 
    threshold-value: uint,
    comparison-type: (string-ascii 3), ;; "gt" for greater than, "lt" for less than
    severity: uint,
    is-active: bool,
    created-at: uint
  }
)

;; Tracks the next available alert ID for each user
(define-map user-alert-counter principal uint)

;; Maps users to their authorized healthcare providers
(define-map authorized-recipients
  { user: principal, recipient-id: uint }
  { recipient: principal, can-view-alerts: bool }
)

;; Maps users to their recipient counter
(define-map user-recipient-counter principal uint)

;; Stores generated alerts based on threshold violations
(define-map generated-alerts
  { user: principal, alert-id: uint, alert-instance-id: uint }
  {
    metric-type: uint,
    recorded-value: uint,
    threshold-value: uint,
    severity: uint,
    timestamp: uint,
    acknowledged: bool
  }
)

;; Maps users to their alert instance counter
(define-map user-alert-instance-counter 
  { user: principal, alert-id: uint }
  uint
)

;; Private functions

;; Get the next alert ID for a user
(define-private (get-next-alert-id (user principal))
  (default-to u1 (map-get? user-alert-counter user))
)

;; Increment and return the next alert ID for a user
(define-private (increment-alert-id (user principal))
  (let ((current-id (get-next-alert-id user)))
    (map-set user-alert-counter user (+ current-id u1))
    current-id
  )
)

;; Get the next recipient ID for a user
(define-private (get-next-recipient-id (user principal))
  (default-to u1 (map-get? user-recipient-counter user))
)

;; Increment and return the next recipient ID for a user
(define-private (increment-recipient-id (user principal))
  (let ((current-id (get-next-recipient-id user)))
    (map-set user-recipient-counter user (+ current-id u1))
    current-id
  )
)

;; Get the next alert instance ID for a specific alert
(define-private (get-next-alert-instance-id (user principal) (alert-id uint))
  (default-to u1 (map-get? user-alert-instance-counter { user: user, alert-id: alert-id }))
)

;; Increment and return the next alert instance ID for a specific alert
(define-private (increment-alert-instance-id (user principal) (alert-id uint))
  (let ((current-id (get-next-alert-instance-id user alert-id)))
    (map-set user-alert-instance-counter { user: user, alert-id: alert-id } (+ current-id u1))
    current-id
  )
)

;; Check if a metric type is valid
(define-private (is-valid-metric-type (metric-type uint))
  (or
    (is-eq metric-type METRIC-HEART-RATE)
    (is-eq metric-type METRIC-BLOOD-PRESSURE)
    (is-eq metric-type METRIC-BLOOD-GLUCOSE)
    (is-eq metric-type METRIC-TEMPERATURE)
    (is-eq metric-type METRIC-OXYGEN-SATURATION)
  )
)

;; Check if a comparison type is valid
(define-private (is-valid-comparison-type (comparison-type (string-ascii 3)))
  (or
    (is-eq comparison-type "gt")
    (is-eq comparison-type "lt")
  )
)

;; Check if a severity level is valid
(define-private (is-valid-severity (severity uint))
  (or
    (is-eq severity SEVERITY-LOW)
    (is-eq severity SEVERITY-MEDIUM)
    (is-eq severity SEVERITY-HIGH)
  )
)

;; Check if a threshold has been exceeded based on comparison type
(define-private (is-threshold-exceeded 
  (recorded-value uint) 
  (threshold-value uint) 
  (comparison-type (string-ascii 3))
)
  (if (is-eq comparison-type "gt")
    (> recorded-value threshold-value)
    (< recorded-value threshold-value)
  )
)

;; Read-only functions

;; Get alert threshold by ID
(define-read-only (get-alert-threshold (user principal) (metric-type uint) (alert-id uint))
  (map-get? alert-thresholds { user: user, metric-type: metric-type, alert-id: alert-id })
)

;; Get all alert thresholds for a user
(define-read-only (get-user-alert-count (user principal))
  (default-to u0 (map-get? user-alert-counter user))
)

;; Get a specific generated alert instance
(define-read-only (get-alert-instance 
  (user principal) 
  (alert-id uint) 
  (alert-instance-id uint)
)
  (map-get? generated-alerts 
    { user: user, alert-id: alert-id, alert-instance-id: alert-instance-id }
  )
)

;; Check if sender is authorized to manage user's alerts
(define-read-only (is-authorized-for-user (sender principal) (user principal))
  (or 
    (is-eq sender user)
    (default-to 
      false 
      (get can-view-alerts 
        (default-to 
          { recipient: sender, can-view-alerts: false }
          (map-get? authorized-recipients 
            { user: user, recipient-id: u0 } ;; placeholder to handle the search
          )
        )
      )
    )
  )
)

;; Public functions

;; Create a new alert threshold
(define-public (create-alert-threshold
  (metric-type uint)
  (threshold-value uint)
  (comparison-type (string-ascii 3))
  (severity uint)
)
  (let
    ((user tx-sender)
     (alert-id (increment-alert-id user))
     (current-time (unwrap-panic (get-block-info? time (- block-height u1)))))
    
    ;; Input validation
    (asserts! (is-valid-metric-type metric-type) ERR-INVALID-METRIC-TYPE)
    (asserts! (is-valid-comparison-type comparison-type) ERR-INVALID-THRESHOLD)
    (asserts! (is-valid-severity severity) ERR-INVALID-THRESHOLD)
    
    ;; Create the alert threshold
    (map-set alert-thresholds
      { user: user, metric-type: metric-type, alert-id: alert-id }
      { 
        threshold-value: threshold-value,
        comparison-type: comparison-type,
        severity: severity,
        is-active: true,
        created-at: current-time
      }
    )
    
    (ok alert-id)
  )
)

;; Update an existing alert threshold
(define-public (update-alert-threshold
  (metric-type uint)
  (alert-id uint)
  (threshold-value uint)
  (comparison-type (string-ascii 3))
  (severity uint)
  (is-active bool)
)
  (let
    ((user tx-sender)
     (existing-alert (get-alert-threshold user metric-type alert-id)))
    
    ;; Check if alert exists
    (asserts! (is-some existing-alert) ERR-ALERT-NOT-FOUND)
    
    ;; Input validation
    (asserts! (is-valid-comparison-type comparison-type) ERR-INVALID-THRESHOLD)
    (asserts! (is-valid-severity severity) ERR-INVALID-THRESHOLD)
    
    ;; Update the alert threshold
    (map-set alert-thresholds
      { user: user, metric-type: metric-type, alert-id: alert-id }
      { 
        threshold-value: threshold-value,
        comparison-type: comparison-type,
        severity: severity,
        is-active: is-active,
        created-at: (get created-at (unwrap-panic existing-alert))
      }
    )
    
    (ok true)
  )
)

;; Delete an alert threshold
(define-public (delete-alert-threshold (metric-type uint) (alert-id uint))
  (let ((user tx-sender))
    ;; Check if alert exists
    (asserts! (is-some (get-alert-threshold user metric-type alert-id)) ERR-ALERT-NOT-FOUND)
    
    ;; Delete the alert threshold
    (map-delete alert-thresholds { user: user, metric-type: metric-type, alert-id: alert-id })
    
    (ok true)
  )
)

;; Record a health measurement and check for alerts
(define-public (record-health-measurement
  (user principal)
  (metric-type uint)
  (recorded-value uint)
)
  (let
    ((sender tx-sender)
     (current-time (unwrap-panic (get-block-info? time (- block-height u1)))))
    
    ;; Check if sender is authorized
    (asserts! (is-authorized-for-user sender user) ERR-NOT-AUTHORIZED)
    (asserts! (is-valid-metric-type metric-type) ERR-INVALID-METRIC-TYPE)
    
    ;; Process alerts for this measurement
    (process-alerts user metric-type recorded-value current-time)
  )
)

;; Helper function to process alerts for a measurement
(define-private (process-alerts
  (user principal)
  (metric-type uint)
  (recorded-value uint)
  (timestamp uint)
)
  (let
    ((alert-count (get-user-alert-count user)))
    
    ;; Iterate through all alert IDs (we can't actually iterate in Clarity,
    ;; but this is a conceptual approach - in reality, you'd need another way to track active alerts)
    (ok true)
  )
)

;; Check a specific alert threshold against a recorded value
(define-public (check-alert-threshold
  (user principal)
  (metric-type uint)
  (alert-id uint)
  (recorded-value uint)
)
  (let
    ((sender tx-sender)
     (threshold-data (get-alert-threshold user metric-type alert-id))
     (current-time (unwrap-panic (get-block-info? time (- block-height u1)))))
    
    ;; Check if sender is authorized
    (asserts! (is-authorized-for-user sender user) ERR-NOT-AUTHORIZED)
    
    ;; Check if alert exists
    (asserts! (is-some threshold-data) ERR-ALERT-NOT-FOUND)
    
    (let
      ((unwrapped-threshold (unwrap-panic threshold-data))
       (threshold-value (get threshold-value unwrapped-threshold))
       (comparison-type (get comparison-type unwrapped-threshold))
       (severity (get severity unwrapped-threshold))
       (is-active (get is-active unwrapped-threshold)))
      
      ;; Check if alert is active
      (if (and 
           is-active 
           (is-threshold-exceeded recorded-value threshold-value comparison-type))
        (let
          ((alert-instance-id (increment-alert-instance-id user alert-id)))
          
          ;; Create alert instance
          (map-set generated-alerts
            { user: user, alert-id: alert-id, alert-instance-id: alert-instance-id }
            {
              metric-type: metric-type,
              recorded-value: recorded-value,
              threshold-value: threshold-value,
              severity: severity,
              timestamp: current-time,
              acknowledged: false
            }
          )
          
          (ok alert-instance-id)
        )
        (ok u0) ;; No alert triggered
      )
    )
  )
)

;; Acknowledge an alert instance
(define-public (acknowledge-alert (alert-id uint) (alert-instance-id uint))
  (let
    ((user tx-sender)
     (alert-data (get-alert-instance user alert-id alert-instance-id)))
    
    ;; Check if alert instance exists
    (asserts! (is-some alert-data) ERR-ALERT-NOT-FOUND)
    
    (let ((unwrapped-alert (unwrap-panic alert-data)))
      ;; Update alert acknowledgment status
      (map-set generated-alerts
        { user: user, alert-id: alert-id, alert-instance-id: alert-instance-id }
        (merge unwrapped-alert { acknowledged: true })
      )
      
      (ok true)
    )
  )
)

;; Add an authorized healthcare provider or recipient for alerts
(define-public (add-authorized-recipient (recipient principal) (can-view-alerts bool))
  (let
    ((user tx-sender)
     (recipient-id (increment-recipient-id user)))
    
    ;; Set the recipient
    (map-set authorized-recipients
      { user: user, recipient-id: recipient-id }
      { recipient: recipient, can-view-alerts: can-view-alerts }
    )
    
    (ok recipient-id)
  )
)

;; Remove an authorized healthcare provider
(define-public (remove-authorized-recipient (recipient-id uint))
  (let ((user tx-sender))
    ;; Check if recipient exists
    (asserts! (is-some (map-get? authorized-recipients { user: user, recipient-id: recipient-id })) 
              ERR-RECIPIENT-NOT-FOUND)
    
    ;; Remove the recipient
    (map-delete authorized-recipients { user: user, recipient-id: recipient-id })
    
    (ok true)
  )
)

;; Update recipient permissions
(define-public (update-recipient-permissions (recipient-id uint) (can-view-alerts bool))
  (let
    ((user tx-sender)
     (recipient-data (map-get? authorized-recipients { user: user, recipient-id: recipient-id })))
    
    ;; Check if recipient exists
    (asserts! (is-some recipient-data) ERR-RECIPIENT-NOT-FOUND)
    
    ;; Update permissions
    (map-set authorized-recipients
      { user: user, recipient-id: recipient-id }
      (merge (unwrap-panic recipient-data) { can-view-alerts: can-view-alerts })
    )
    
    (ok true)
  )
)