;; photon-health-network

(define-data-var total-vault-entries uint u0)

;; Administrative control designation
(define-constant vault-overseer tx-sender)

;; Operational response codes for system interactions
(define-constant ERR_OVERSIZED_PAYLOAD (err u304))
(define-constant ERR_INVALID_AUTH_TOKEN (err u305))
(define-constant ERR_UNKNOWN_PRACTITIONER (err u306))
(define-constant ERR_CORRUPTED_ID_FORMAT (err u303))
(define-constant ERR_FORBIDDEN_TAG_TYPE (err u307))
(define-constant ERR_PERMISSION_BREACH (err u308))
(define-constant ERR_RESTRICTED_ADMIN_OP (err u300))
(define-constant ERR_VAULT_ENTRY_ABSENT (err u301))
(define-constant ERR_DUPLICATE_VAULT_ENTRY (err u302))

;; Core medical record storage mapping
(define-map quantum-vault-records
  { vault-entry-id: uint }
  {
    patient-hash-code: (string-ascii 64),
    medical-authority: principal,
    payload-byte-size: uint,
    creation-block: uint,
    diagnostic-notes: (string-ascii 128),
    classification-tags: (list 10 (string-ascii 32))
  }
)

;; Access permission control mapping
(define-map vault-access-permissions
  { vault-entry-id: uint, accessor-principal: principal }
  { has-access-rights: bool }
)

;; Private helper function for tag format verification
(define-private (check-tag-validity (single-tag (string-ascii 32)))
  (and 
    (> (len single-tag) u0)
    (< (len single-tag) u33)
  )
)

;; Private helper for comprehensive tag collection validation
(define-private (verify-tag-collection (tag-array (list 10 (string-ascii 32))))
  (and
    (> (len tag-array) u0)
    (<= (len tag-array) u10)
    (is-eq (len (filter check-tag-validity tag-array)) (len tag-array))
  )
)

;; Utility function to confirm vault entry existence
(define-private (vault-entry-exists? (entry-id uint))
  (is-some (map-get? quantum-vault-records { vault-entry-id: entry-id }))
)

;; Authorization verification for medical authority
(define-private (confirm-medical-authority? (entry-id uint) (authority-principal principal))
  (match (map-get? quantum-vault-records { vault-entry-id: entry-id })
    record-data (is-eq (get medical-authority record-data) authority-principal)
    false
  )
)

;; Payload size retrieval helper function
(define-private (fetch-payload-size (entry-id uint))
  (default-to u0
    (get payload-byte-size
      (map-get? quantum-vault-records { vault-entry-id: entry-id })
    )
  )
)

;; Primary function for creating new medical vault entries
(define-public (create-vault-entry 
  (patient-hash-code (string-ascii 64))
  (payload-byte-size uint)
  (diagnostic-notes (string-ascii 128))
  (classification-tags (list 10 (string-ascii 32)))
)
  (let
    (
      (new-entry-id (+ (var-get total-vault-entries) u1))
    )
    (asserts! (> (len patient-hash-code) u0) ERR_CORRUPTED_ID_FORMAT)
    (asserts! (< (len patient-hash-code) u65) ERR_CORRUPTED_ID_FORMAT)
    (asserts! (> payload-byte-size u0) ERR_OVERSIZED_PAYLOAD)
    (asserts! (< payload-byte-size u1000000000) ERR_OVERSIZED_PAYLOAD)
    (asserts! (> (len diagnostic-notes) u0) ERR_CORRUPTED_ID_FORMAT)
    (asserts! (< (len diagnostic-notes) u129) ERR_CORRUPTED_ID_FORMAT)
    (asserts! (verify-tag-collection classification-tags) ERR_FORBIDDEN_TAG_TYPE)

    (map-insert quantum-vault-records
      { vault-entry-id: new-entry-id }
      {
        patient-hash-code: patient-hash-code,
        medical-authority: tx-sender,
        payload-byte-size: payload-byte-size,
        creation-block: block-height,
        diagnostic-notes: diagnostic-notes,
        classification-tags: classification-tags
      }
    )

    (map-insert vault-access-permissions
      { vault-entry-id: new-entry-id, accessor-principal: tx-sender }
      { has-access-rights: true }
    )

    (var-set total-vault-entries new-entry-id)
    (ok new-entry-id)
  )
)

;; Function to transfer medical authority ownership
(define-public (transfer-medical-authority (entry-id uint) (new-authority-principal principal))
  (let
    (
      (current-record (unwrap! (map-get? quantum-vault-records { vault-entry-id: entry-id }) ERR_VAULT_ENTRY_ABSENT))
    )
    (asserts! (vault-entry-exists? entry-id) ERR_VAULT_ENTRY_ABSENT)
    (asserts! (is-eq (get medical-authority current-record) tx-sender) ERR_INVALID_AUTH_TOKEN)

    (map-set quantum-vault-records
      { vault-entry-id: entry-id }
      (merge current-record { medical-authority: new-authority-principal })
    )
    (ok true)
  )
)

;; Retrieval function for classification tags
(define-public (get-classification-tags (entry-id uint))
  (let
    (
      (vault-record (unwrap! (map-get? quantum-vault-records { vault-entry-id: entry-id }) ERR_VAULT_ENTRY_ABSENT))
    )
    (ok (get classification-tags vault-record))
  )
)

;; Function to obtain medical authority information
(define-public (get-medical-authority (entry-id uint))
  (let
    (
      (vault-record (unwrap! (map-get? quantum-vault-records { vault-entry-id: entry-id }) ERR_VAULT_ENTRY_ABSENT))
    )
    (ok (get medical-authority vault-record))
  )
)

;; Timestamp retrieval for vault entries
(define-public (get-creation-timestamp (entry-id uint))
  (let
    (
      (vault-record (unwrap! (map-get? quantum-vault-records { vault-entry-id: entry-id }) ERR_VAULT_ENTRY_ABSENT))
    )
    (ok (get creation-block vault-record))
  )
)

;; System-wide vault entry count query
(define-public (get-total-vault-count)
  (ok (var-get total-vault-entries))
)

;; Payload size information retrieval
(define-public (get-entry-payload-size (entry-id uint))
  (let
    (
      (vault-record (unwrap! (map-get? quantum-vault-records { vault-entry-id: entry-id }) ERR_VAULT_ENTRY_ABSENT))
    )
    (ok (get payload-byte-size vault-record))
  )
)

;; Diagnostic notes access function
(define-public (get-diagnostic-summary (entry-id uint))
  (let
    (
      (vault-record (unwrap! (map-get? quantum-vault-records { vault-entry-id: entry-id }) ERR_VAULT_ENTRY_ABSENT))
    )
    (ok (get diagnostic-notes vault-record))
  )
)

;; Access rights verification function
(define-public (check-access-permissions (entry-id uint) (accessor-principal principal))
  (let
    (
      (permission-record (unwrap! (map-get? vault-access-permissions { vault-entry-id: entry-id, accessor-principal: accessor-principal }) ERR_PERMISSION_BREACH))
    )
    (ok (get has-access-rights permission-record))
  )
)

;; Comprehensive vault entry metadata update function
(define-public (modify-vault-metadata 
  (entry-id uint)
  (updated-patient-hash (string-ascii 64))
  (updated-payload-size uint)
  (updated-diagnostic-notes (string-ascii 128))
  (updated-classification-tags (list 10 (string-ascii 32)))
)
  (let
    (
      (existing-record (unwrap! (map-get? quantum-vault-records { vault-entry-id: entry-id }) ERR_VAULT_ENTRY_ABSENT))
    )
    (asserts! (vault-entry-exists? entry-id) ERR_VAULT_ENTRY_ABSENT)
    (asserts! (is-eq (get medical-authority existing-record) tx-sender) ERR_INVALID_AUTH_TOKEN)
    (asserts! (> (len updated-patient-hash) u0) ERR_CORRUPTED_ID_FORMAT)
    (asserts! (< (len updated-patient-hash) u65) ERR_CORRUPTED_ID_FORMAT)
    (asserts! (> updated-payload-size u0) ERR_OVERSIZED_PAYLOAD)
    (asserts! (< updated-payload-size u1000000000) ERR_OVERSIZED_PAYLOAD)
    (asserts! (> (len updated-diagnostic-notes) u0) ERR_CORRUPTED_ID_FORMAT)
    (asserts! (< (len updated-diagnostic-notes) u129) ERR_CORRUPTED_ID_FORMAT)
    (asserts! (verify-tag-collection updated-classification-tags) ERR_FORBIDDEN_TAG_TYPE)

    (map-set quantum-vault-records
      { vault-entry-id: entry-id }
      (merge existing-record { 
        patient-hash-code: updated-patient-hash, 
        payload-byte-size: updated-payload-size, 
        diagnostic-notes: updated-diagnostic-notes, 
        classification-tags: updated-classification-tags 
      })
    )
    (ok true)
  )
)

