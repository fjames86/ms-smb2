 

(in-package :ms-smb2)

;; big-endian 24-bit integers
(packet::define-type :uint24be
    ((uint24 buffer start)
	 (declare (integer uint24))
     (packet::pack-bytes (nreverse (packet::bytes uint24 3)) buffer start))
  ((buffer start)
   (packet::unpack-bytes (reverse (subseq buffer start (+ start 3)))
                         start 3))
  3)

;; SMB v1 transport header
;; 2.1 Transport http://msdn.microsoft.com/en-us/library/cc246249.aspx
;; Note: the length must be in network byte order (i.e. big-endian)
(defpacket smb-transport-header 
  ((zero :uint8 :initform 0)
   (length :uint24be :initform 0 :initarg :length)
   ;; payload 
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))



;; 2.2.1.1 SMB2 Packet Header - ASYNC http://msdn.microsoft.com/en-us/library/cc246528.aspx
(defpacket header-async 
  ((protocol-id (:uint8 4) :initform #(#xfe #x53 #x4d #x42)) ;; #(#xfe 'S' 'M' 'B')
   (structure-size :uint16 :initform 64)
   (credit-charge :uint16 :initform 0 :initarg :credit-charge :accessor header-credit-charge)
;;   (channel-sequence :uint16 :initform 0 :initarg :channel-sequence :accessor header-channel-sequence)
;;   (reserved :uint16 :initform 0)
   (status :uint32 :initform 0 :initarg :status :accessor header-status)
   (command :uint16 :initform 0 :initarg :command :accessor header-command)
   (credit-request :uint16 :initform 0 :initarg :credit-request :accessor header-credit-request)
   (flags :uint32 :initform 0 :initarg :flags :accessor header-flags)
   (next-command :uint32 :initform 0 :initarg :next-command :accessor header-next-command)
   (message-id :uint64 :initform 0 :initarg :message-id :accessor header-message-id)
   (async-id :uint64 :initform 0 :initarg :async-id :accessor header-async-id)
   (session-id :uint64 :initform 0 :initarg :session-id :accessor header-session-id)
   (signature (:uint8 16) :initform nil :initarg :signature :accessor header-signature))
  (:packing 1))

(defpacket header-sync 
  ((protocol-id (:uint8 4) :initform #(#xfe #x53 #x4d #x42)) ;; #(#xfe 'S' 'M' 'B')
   (structure-size :uint16 :initform 64)
   (credit-charge :uint16 :initform 0 :initarg :credit-charge :accessor header-credit-charge)
;;   (channel-sequence :uint16 :initform 0 :initarg :channel-sequence :accessor header-channel-sequence)
;;   (reserved :uint16 :initform 0)
   (status :uint32 :initform 0 :initarg :status :accessor header-status)
   (command :uint16 :initform 0 :initarg :command :accessor header-command)
   (credit-request :uint16 :initform 0 :initarg :credit-request :accessor header-credit-request)
   (flags :uint32 :initform 0 :initarg :flags :accessor header-flags)
   (next-command :uint32 :initform 0 :initarg :next-command :accessor header-next-command)
   (message-id :uint64 :initform 0 :initarg :message-id :accessor header-message-id)
   (reserved2 :uint32 :initform 0)
   (tree-id :uint32 :initform 0 :initarg :tree-id :accessor header-tree-id)
   (session-id :uint64 :initform 0 :initarg :session-id :accessor header-session-id)
   (signature (:uint8 16) :initform nil :initarg :signature :accessor header-signature))
  (:packing 1))

(defenum *commands*
  ((:NEGOTIATE #x0000)
   (:SESSION-SETUP #x0001)
   (:LOGOFF #x0002)
   (:TREE-CONNECT #x0003)
   (:TREE-DISCONNECT #x0004)
   (:CREATE #x0005)
   (:CLOSE #x0006)
   (:FLUSH #x0007)
   (:READ #x0008)
   (:WRITE #x0009)
   (:LOCK #x000A)
   (:IOCTL #x000B)
   (:CANCEL #x000C)
   (:ECHO #x000D)
   (:QUERY-DIRECTORY #x000E)
   (:CHANGE-NOTIFY #x000F)
   (:QUERY-INFO #x0010)
   (:SET-INFO #x0011)
   (:OPLOCK-BREAK #x0012)))

(defflags *header-flags*
  ((:SERVER-TO-REDIR 0
    "When set, indicates the message is a response rather than a request. This MUST be set on responses sent from the server to the client, and MUST NOT be set on requests sent from the client to the server.")
   (:ASYNC-COMMAND 1
    "When set, indicates that this is an ASYNC SMB2 header. Always set for headers of the form described in this section.")
   (:RELATED-OPERATIONS 2
    "When set in an SMB2 request, indicates that this request is a related operation in a compounded request chain. The use of this flag in an SMB2 request is as specified in 3.2.4.1.4.
When set in an SMB2 compound response, indicates that the request corresponding to this response was part of a related operation in a compounded request chain. The use of this flag in an SMB2 response is as specified in 3.3.5.2.7.2.")
   (:SIGNED 3
    "When set, indicates that this packet has been signed. The use of this flag is as specified in 3.1.5.1.")
   (:DFS-OPERATIONS 28
    "When set, indicates that this command is a Distributed File System (DFS) operation. The use of this flag is as specified in 3.3.5.9.")
   (:REPLAY-OPERATION 29
    "This flag is only valid for the SMB 3.x dialect family. When set, it indicates that this command is a replay operation. The client MUST ignore this bit on receipt.")))


;; 2.2.2 SMB2 ERROR Response http://msdn.microsoft.com/en-us/library/cc246530.aspx
(defpacket error-response
  ((structure-size :uint16 :initform 9)
   (reserved :uint16 :initform 0)
   ;; payload
   (error-data (:uint8 0) :initform nil :initarg :error-data :accessor packet-buffer))
  (:packing 1))

(defun pack-error-response (data)
  (let ((rsp (make-instance 'error-reponse)))
    (if (null data)
        (setf (error-response-data rsp) #(0))
        (setf (error-response-data rsp) data))
    (pack rsp 'error-response)))

(defun unpack-error-response (buffer)
  (multiple-value-bind (rsp payload) (unpack buffer 'error-response)
    (setf (error-response-data rsp) payload)
    rsp))

;; 2.2.2.1 Symbolic Link Error Response http://msdn.microsoft.com/en-us/library/cc246542.aspx
(defpacket symlink-error-response
  ((symlink-length :uint32 :initform 0 :initarg :symlink-length :accessor symlink-error-response-length)
   (symlink-error-tag :uint32 :initform #x4C4D5953)
   (reparse-tag :uint32 :initform #xA000000C)
   (reparse-length :uint16 :initform 0 :initarg :reparse-length :accessor symlink-error-response-reparse-length)
   (unparseed-length :uint16 :initform 0 :initarg :unparsed-length :accessor symlink-error-respinse-unparsed-length)
   (substitute-name-offset :uint16 :initform 0 :initarg :substitute-name-offset)
   (substitute-name-length :uint16 :initform 0 :initarg :substitute-name-length)
   (print-name-offset :uint16 :initform 0 :initarg :print-name-offset)
   (print-name-length :uint16 :initform 0 :initarg :print-name-length)
   (flags :uint32 :initform 0 :initarg :flags)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))


;; 2.2.3 SMB2 NEGOTIATE Request http://msdn.microsoft.com/en-us/library/cc246543.aspx
(defpacket negotiate-request 
  ((structure-size :uint16 :initform 36)
   (dialect-count :uint16 :initform 0 :initarg :dialect-count)
   (security-mode :uint16 :initform 1 :initarg :security-mode)
   (reserved :uint16 :initform 0)
   (capabilities :uint32 :initform 0 :initarg :capabilities)
   (client-guid (:uint8 16) :initform nil :initarg :client-guid)
   (client-start-time :uint64 :initform 0)
   ;; payload
   (dialects (:uint16 0) :initform nil :accessor packet-buffer))
  (:packing 1))

(defenum *negotiate-request-modes*
  ((:NEGOTIATE-SIGNING-ENABLED #x0001
   "When set, indicates that security signatures are enabled on the client. The client MUST set this bit if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is not set, and MUST NOT set this bit if the SMB2_NEGOTIATE_SIGNING_REQUIRED bit is set. The server MUST ignore this bit.")
   (:NEGOTIATE-SIGNING-REQUIRED #x0002
    "When set, indicates that security signatures are required by the client.")))

(defflags *negotiate-request-capabilities*
  ((:GLOBAL-CAP-DFS 0
    "When set, indicates that the client supports the Distributed File System (DFS).")
   (:GLOBAL-CAP-LEASING 1
    "When set, indicates that the client supports leasing.")
   (:GLOBAL-CAP-LARGE-MTU 2
    "When set, indicates that the client supports multi-credit operations.")
   (:GLOBAL-CAP-MULTI-CHANNEL 3
    "When set, indicates that the client supports establishing multiple channels for a single session.")
   (:GLOBAL-CAP-PERSISTENT-HANDLES 4
    "When set, indicates that the client supports persistent handles.")
   (:GLOBAL-CAP-DIRECTORY-LEASING 5
    "When set, indicates that the client supports directory leasing.")
   (:GLOBAL-CAP-ENCRYPTION 6
    "When set, indicates that the client supports encryption.")))

(defenum *negotiate-request-dialects*
  ((:smb-2.002 #x0202
   "SMB 2.002 dialect revision number.")
   (:smb-2.1 #x0210
    "SMB 2.1 dialect revision number.")
   (:smb-3.0 #x0300
    "SMB 3.0 dialect revision number.")
   (:smb-3.02 #x0302
    "SMB 3.02 dialect revision number.")))

;; 2.2.4 SMB2 NEGOTIATE Response http://msdn.microsoft.com/en-us/library/cc246561.aspx
(defpacket negotiate-response 
  ((structure-size :uint16 :initform 65)
   (security-mode :uint16 :initform 0 :initarg :security-mode)
   (dialect-revision :uint16 :initform 0 :initarg :dialect-revision)
   (reserved :uint16 :initform 0)
   (server-guid (:uint8 16) :initform nil :initarg :server-guid)
   (capabilities :uint32 :initform 0 :initarg :capabilities)
   (max-transact-size :uint32 :initform 0 :initarg :max-transact-size)
   (max-read-size :uint32 :initform 0 :initarg :max-read-size)
   (max-write-size :uint32 :initform 0 :initarg :max-write-size)
   (system-time :uint64 :initform 0)
   (server-start-time :uint64 :initform 0)
   (server-buffer-offset :uint16 :initform 0)
   (server-buffer-length :uint16 :initform 0)
   (reserved2 :uint32 :initform 0)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))


;; 2.2.5 SMB2 SESSION_SETUP Request http://msdn.microsoft.com/en-us/library/cc246563.aspx
(defpacket session-setup-request 
  ((structure-size :uint16 :initform 25)
   (flags :uint8 :initform 0 :initarg :flags)
   (security-mode :uint8 :initform 0 :initarg :security-mode)
   (capabilities :uint32 :initform 0 :initarg :capabilities)
   (channel :uint32 :initform 0)
   (security-buffer-offset :uint16 :initform 0 :initarg :security-buffer-offset)
   (security-buffer-length :uint16 :initform 0 :initarg :security-buffer-length)
   (previous-session-id (:uint8 8) :initform nil :initarg :previous-session-id)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))


;; 2.2.6 SMB2 SESSION_SETUP Response http://msdn.microsoft.com/en-us/library/cc246564.aspx
(defpacket session-setup-response 
  ((structure-size :uint16 :initform 9)
   (flags :uint16 :initform 0 :initarg :flags)
   (security-buffer-offset :uint16 :initform 0 :initarg :security-buffer-offset)
   (security-buffer-length :uint16 :initform 0 :initarg :security-buffer-length)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

(defflags *session-setup-flags*
  ((:SESSION-FLAG-IS-GUEST #x0001
    "If set, the client has been authenticated as a guest user.")
   (:SESSION-FLAG-IS-NULL #x0002
    "If set, the client has been authenticated as an anonymous user.")
   (:SESSION-FLAG-ENCRYPT-DATA #x0004
    "If set, the server requires encryption of messages on this session, per the conditions specified in section 3.3.5.2.9. This flag is only valid for the SMB 3.x dialect family.")))

   
;; 2.2.7 SMB2 LOGOFF Request http://msdn.microsoft.com/en-us/library/cc246565.aspx
(defpacket logoff-request 
  ((structure-size :uint16 :initform 4)
   (reserved :uint16 :initform 0))
  (:packing 1))

;; 2.2.8 SMB2 LOGOFF Response http://msdn.microsoft.com/en-us/library/cc246566.aspx
(defpacket logoff-response
  ((structure-size :uint16 :initform 4)
   (reserved :uint16 :initform 0))
  (:packing 1))

;; 2.2.9 SMB2 TREE_CONNECT Request http://msdn.microsoft.com/en-us/library/cc246567.aspx
(defpacket tree-connect-request 
  ((structure-size :uint16 :initform 9)
   (reserved :uint16 :initform 0)
   (path-offset :uint16 :initform 0 :initarg :path-offset)
   (path-length :uint16 :initform 0 :initarg :path-length)
    ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.10 SMB2 TREE_CONNECT Response http://msdn.microsoft.com/en-us/library/cc246499.aspx
(defpacket tree-connect-response 
  ((structure-size :uint16 :initform 16)
   (share-type :uint8 :initform 0 :accessor :share-type)
   (reserved :uint8 :initform 0)
   (share-flags :uint32 :initform 0 :initarg :share-flags)
   (capabilities :uint32 :initform 0 :initarg :capabilities)
   (minimal-access :uint32 :initform 0 :initarg :minimal-access))
  (:packing 1))

(defflags *tree-connect-flags*
  ((:MANUAL-CACHING 0
    "The client may cache files that are explicitly selected by the user for offline use.")
   (:AUTO-CACHING 4
    "The client may automatically cache files that are used by the user for offline access.")
   (:VDO-CACHING 5
    "The client may automatically cache files that are used by the user for offline access and may use those files in an offline mode even if the share is available.")
   (:NO-CACHING 6
    "Offline caching MUST NOT occur.")
   (:DFS 0
    "The specified share is present in a Distributed File System (DFS) tree structure. The server SHOULD set the SMB2_SHAREFLAG_DFS bit in the ShareFlags field if the per-share property Share.IsDfs is TRUE.")
   (:DFS-ROOT 1
    "The specified share is present in a DFS tree structure. The server SHOULD set the SMB2_SHAREFLAG_DFS_ROOT bit in the ShareFlags field if the per-share property Share.IsDfs is TRUE.")
   (:RESTRICT-EXCLUSIVE-OPENS 8
    "The specified share disallows exclusive file opens that deny reads to an open file.")
   (:FORCE-SHARED-DELETE 9
    "The specified share disallows clients from opening files on the share in an exclusive mode that prevents the file from being deleted until the client closes the file.")
   (:ALLOW-NAMESPACE-CACHING 10
    "The client MUST ignore this flag.")
   (:ACCESS-BASED-DIRECTORY-ENUM 11
    "The server will filter directory entries based on the access permissions of the client.")
   (:FORCE-LEVELII-OPLOCK 12
    "The server will not issue exclusive caching rights on this share.<27>")
   (:ENABLE-HASH-V1 13
    "The share supports hash generation for branch cache retrieval of data. For more information, see section 2.2.31.2. This flag is not valid for the SMB 2.002 dialect.")
   (:ENABLE-HASH-V2 14
    "The share supports v2 hash generation for branch cache retrieval of data. For more information, see section 2.2.31.2. This flag is not valid for the SMB 2.002 and SMB 2.1 dialects.")
   (:ENCRYPT-DATA 15
    "The server requires encryption of remote file access messages on this share, per the conditions specified in section 3.3.5.2.11. This flag is only valid for the SMB 3.x dialect family.")))

(defflags *share-capabilities*
  ((:DFS #x00000008
    "The specified share is present in a DFS tree structure. The server MUST set the SMB2_SHARE_CAP_DFS bit in the Capabilities field if the per-share property Share.IsDfs is TRUE.")
   (:CONTINUOUS-AVAILABILITY #x00000010
    "The specified share is continuously available. This flag is only valid for the SMB 3.x dialect family.")
   (:SCALEOUT #x00000020
    "The specified share is present on a server configuration which facilitates faster recovery of durable handles. This flag is only valid for the SMB 3.x dialect family.")
   (:CLUSTER #x00000040
    "The specified share is present on a server configuration which provides monitoring of the availability of share through the Witness service specified in [MS-SWN]. This flag is only valid for the SMB 3.x dialect family.")
   (:ASYMMETRIC #x00000080
    "The specified share is present on a server configuration that allows dynamic changes in the ownership of the share. This flag is only valid for the SMB 3.02 dialect.")))

;; 2.2.11 SMB2 TREE_DISCONNECT Request http://msdn.microsoft.com/en-us/library/cc246500.aspx
(defpacket tree-disconnect-request
  ((structure-size :uint16 :initform 4)
   (reserved :uint16 :initform 0))
  (:packing 1))

;; 2.2.12 SMB2 TREE_DISCONNECT Response http://msdn.microsoft.com/en-us/library/cc246501.aspx
(defpacket tree-disconnect-response
  ((structure-size :uint16 :initform 4)
   (reserved :uint16 :initform 0))
  (:packing 1))

;; 2.2.13 SMB2 CREATE Request http://msdn.microsoft.com/en-us/library/cc246502.aspx
(defpacket create-request 
  ((structure-size :uint16 :initform 57)
   (security-flags :uint8 :initform 0)
   (requested-oplock-level :uint8 :initform 0 :initarg :requested-oplock-level)
   (impersonation-level :uint32 :initform 0 :initarg :impersonation-level)
   (smb-create-flags :uint64 :initform 0)
   (reserved :uint64 :initform 0)
   (desired-access :uint32 :initform 0 :initarg :desired-access)
   (file-attributes :uint32 :initform 0 :initarg :file-attributes)
   (share-access :uint32 :initform 0 :initarg :share-access)
   (create-disposition :uint32 :initform 0 :initarg :create-disposition)
   (create-options :uint32 :initform 0 :initarg :create-options)
   (name-offset :uint16 :initform 0 :initarg :name-offset)
   (name-length :uint16 :initform 0 :initarg :name-length)
   (create-context-offset :uint32 :initform 0 :initarg :create-context-offset)
   (create-context-length :uint32 :initform 0 :initarg :create-context-length)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

(defenum *oplock-level*
  ((:NONE #x00
    "No oplock is requested.")
   (:II #x01
    "A level II oplock is requested.")
   (:EXCLUSIVE #x08
    "An exclusive oplock is requested.")
   (:BATCH #x09
    "A batch oplock is requested.")
   (:LEASE #xFF
    "A lease is requested. If set, the request packet MUST contain an SMB2_CREATE_REQUEST_LEASE (section 2.2.13.2.8) create context. This value is not valid for the SMB 2.002 dialect.")))

(defenum *impersonation-level*
  ((:Anonymous #x00000000
    "The application-requested impersonation level is Anonymous.")
   (:Identification #x00000001
    "The application-requested impersonation level is Identification.")
   (:Impersonation #x00000002
    "The application-requested impersonation level is Impersonation.")
   (:Delegate #x00000003
    "The application-requested impersonation level is Delegate.")))

(defflags *share-access*
  ((:READ #x00000001
    "When set, indicates that other  opens are allowed to read this file while this open is present. This bit MUST NOT be set for a named pipe or a printer file. Each open creates a new instance of a named pipe. Likewise, opening a printer file always creates a new file.")
   (:WRITE #x00000002
    "When set, indicates that other opens are allowed to write this file while this open is present. This bit MUST NOT be set for a named pipe or a printer file. Each open creates a new instance of a named pipe. Likewise, opening a printer file always creates a new file.")
   (:DELETE #x00000004
    "When set, indicates that other opens are allowed to delete or rename this file while this open is present. This bit MUST NOT be set for a named pipe or a printer file. Each open creates a new instance of a named pipe. Likewise, opening a printer file always creates a new file.")))

(defenum *create-disposition*
  ((:SUPERSEDE #x00000000
   "If the file already exists, supersede it. Otherwise, create the file. This value SHOULD NOT be used for a printer object.")
   (:OPEN #x00000001
    "If the file already exists, return success; otherwise, fail the operation. MUST NOT be used for a printer object.")
   (:CREATE #x00000002
    "If the file already exists, fail the operation; otherwise, create the file.")
   (:OPEN-IF #x00000003
    "Open the file if it already exists; otherwise, create the file. This value SHOULD NOT be used for a printer object.")
   (:OVERWRITE #x00000004
    "Overwrite the file if it already exists; otherwise, fail the operation. MUST NOT be used for a printer object.")
   (:OVERWRITE-IF #x00000005
     "Overwrite the file if it already exists; otherwise, create the file. This value SHOULD NOT be used for a printer object.")))


(defflags *create-options* 
  ((:DIRECTORY-FILE 0
   "The file being created or opened is a directory file. With this flag, the CreateDisposition field MUST be set to FILE_CREATE, FILE_OPEN_IF, or FILE_OPEN. With this flag, only the following CreateOptions values are valid: FILE_WRITE_THROUGH, FILE_OPEN_FOR_BACKUP_INTENT, FILE_DELETE_ON_CLOSE, and FILE_OPEN_REPARSE_POINT. If the file being created or opened already exists and is not a directory file and FILE_CREATE is specified in the CreateDisposition field, then the server MUST fail the request with STATUS_OBJECT_NAME_COLLISION. If the file being created or opened already exists and is not a directory file and FILE_CREATE is not specified in the CreateDisposition field, then the server MUST fail the request with STATUS_NOT_A_DIRECTORY. The server MUST fail an invalid CreateDisposition field or an invalid combination of CreateOptions flags with STATUS_INVALID_PARAMETER.")
  (:WRITE-THROUGH 1
   "The server MUST propagate writes to this open to persistent storage before returning success to the client on write operations.")
   (:SEQUENTIAL-ONLY 2
    "This indicates that the application intends to read or write at sequential offsets using this handle, so the server SHOULD optimize for sequential access. However, the server MUST accept any access pattern. This flag value is incompatible with the FILE_RANDOM_ACCESS value.")
   (:NO-INTERMEDIATE-BUFFERING 3
    "The server or underlying object store SHOULD NOT cache data at intermediate layers and SHOULD allow it to flow through to persistent storage.")
   (:SYNCHRONOUS-IO-ALERT 4
    "This bit SHOULD be set to 0  and MUST be ignored by the server.")
   (:SYNCHRONOUS-IO-NONALERT 5
    "This bit SHOULD be set to 0 and MUST be ignored by the server.")
   (:NON-DIRECTORY-FILE 5
    "If the name of the file being created or opened matches with an existing directory file, the server MUST fail the request with STATUS_FILE_IS_A_DIRECTORY. This flag MUST NOT be used with FILE_DIRECTORY_FILE or the server MUST fail the request with STATUS_INVALID_PARAMETER.")
   (:COMPLETE-IF-OPLOCKED 8
    "This bit SHOULD be set to 0 and MUST be ignored by the server.")
   (:NO-EA-KNOWLEDGE 9
    "The caller does not understand how to handle extended attributes. If the request includes an SMB2_CREATE_EA_BUFFER create context, then the server MUST fail this request with STATUS_ACCESS_DENIED. If extended attributes with the FILE_NEED_EA flag (see [MS-FSCC] section 2.4.15) set are associated with the file being opened, then the server MUST fail this request with STATUS_ACCESS_DENIED.")
   (:RANDOM-ACCESS 11
    "This indicates that the application intends to read or write at random offsets using this handle, so the server SHOULD optimize for random access. However, the server MUST accept any access pattern. This flag value is incompatible with the FILE_SEQUENTIAL_ONLY value. If both FILE_RANDOM_ACCESS and FILE_SEQUENTIAL_ONLY are set, then FILE_SEQUENTIAL_ONLY is ignored.")
   (:DELETE-ON-CLOSE 12
    "The file MUST be automatically deleted when the last open request on this file is closed. When this option is set, the DesiredAccess field MUST include the DELETE flag. This option is often used for temporary files.")
   (:OPEN-BY-FILE-ID 13
    "This bit SHOULD be set to 0 and the server MUST fail the request with a STATUS_NOT_SUPPORTED error if this bit is set.")
   (:OPEN-FOR-BACKUP-INTENT 14
    "The file is being opened for backup intent. That is, it is being opened or created for the purposes of either a backup or a restore operation. The server can check to ensure that the caller is capable of overriding whatever security checks have been placed on the file to allow a backup or restore operation to occur. The server can check for access rights to the file before checking the DesiredAccess field.")
   (:NO-COMPRESSION 15
    "The file cannot be compressed. This bit is ignored when FILE_DIRECTORY_FILE is set in CreateOptions.")
   (:OPEN-REMOTE-INSTANCE 10
    "This bit SHOULD be set to 0 and MUST be ignored by the server.")
   (:OPEN-REQUIRING-OPLOCK 16
    "This bit SHOULD be set to 0 and MUST be ignored by the server.")
   (:DISALLOW-EXCLUSIVE 17
    "This bit SHOULD be set to 0 and MUST be ignored by the server.")
   (:RESERVE-OPFILTER 20
    "This bit SHOULD be set to 0 and the server MUST fail the request with a STATUS_NOT_SUPPORTED error if this bit is set.")
   (:OPEN-REPARSE-POINT 21
    "If the file or directory being opened is a reparse point, open the reparse point itself rather than the target that the reparse point references.")
   (:OPEN-NO-RECALL 22
    "In an HSM (Hierarchical Storage Management) environment, this flag means the file SHOULD NOT be recalled from tertiary storage such as tape. The recall can take several minutes. The caller can specify this flag to avoid those delays.")
   (:OPEN-FOR-FREE-SPACE-QUERY 23
    "Open file to query for free space. The client SHOULD set this to 0 and the server MUST ignore it.")))

   
   


;; 2.2.13.1.1 File_Pipe_Printer_Access_Mask http://msdn.microsoft.com/en-us/library/cc246802.aspx
(defflags *file-pipe-printer-acccess-mask*
  ((:READ-DATA 0
    "This value indicates the right to read data from the file or named pipe.")
   (:WRITE-DATA 1
    "This value indicates the right to write data into the file or named pipe beyond the end of the file.")
   (:APPEND-DATA 2
    "This value indicates the right to append data into the file or named pipe.")
   (:READ-EA 3
    "This value indicates the right to read the extended attributes of the file or named pipe.")
   (:WRITE-EA 4
    "This value indicates the right to write or change the extended attributes to the file or named pipe.")
   (:DELETE-CHILD 6
    "This value indicates the right to delete entries within a directory.")
   (:EXECUTE 5
    "This value indicates the right to execute the file.")
   (:READ-ATTRIBUTES 7
    "This value indicates the right to read the attributes of the file.")
   (:WRITE-ATTRIBUTES 8
    "This value indicates the right to change the attributes of the file.")
   (:DELETE 16
    "This value indicates the right to delete the file.")
   (:READ-CONTROL 17
    "This value indicates the right to read the security descriptor for the file or named pipe.")
   (:WRITE-DAC 18
    "This value indicates the right to change the discretionary access control list (DACL) in the security descriptor for the file or named pipe. For the DACL data structure, see ACL in [MS-DTYP].")
   (:WRITE-OWNER 19
    "This value indicates the right to change the owner in the security descriptor for the file or named pipe.")
   (:SYNCHRONIZE 20
    "SMB2 clients set this flag to any value. SMB2 servers SHOULD<41> ignore this flag.")
   (:ACCESS-SYSTEM-SECURITY 24
    "This value indicates the right to read or change the system access control list (SACL) in the security descriptor for the file or named pipe. For the SACL data structure, see ACL in [MS-DTYP].")
   (:MAXIMUM_ALLOWED 25
    "This value indicates that the client is requesting an open to the file with the highest level of access the client has on this file. If no access is granted for the client on this file, the server MUST fail the open with STATUS_ACCESS_DENIED.")
   (:GENERIC-ALL 28
    "This value indicates a request for all the access flags that are previously listed except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY.")
   (:GENERIC-EXECUTE 29
    "This value indicates a request for the following combination of access flags listed above: FILE_READ_ATTRIBUTES| FILE_EXECUTE| SYNCHRONIZE| READ_CONTROL.")
   (:GENERIC-WRITE 30
    "This value indicates a request for the following combination of access flags listed above: FILE_WRITE_DATA| FILE_APPEND_DATA| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL.")
   (:GENERIC-READ 31
    "This value indicates a request for the following combination of access flags listed above: FILE_READ_DATA| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL.")))
   
;; 2.2.13.1.2 Directory_Access_Mask http://msdn.microsoft.com/en-us/library/cc246801.aspx
(defflags *directory-access-mask* 
  ((:LIST-DIRECTORY 0
    "This value indicates the right to enumerate the contents of the directory.")
   (:ADD-FILE 1
    "This value indicates the right to create a file under the directory.")
   (:ADD-SUBDIRECTORY 2
    "This value indicates the right to add a sub-directory under the directory.")
   (:READ-EA 3
    "This value indicates the right to read the extended attributes of the directory.")
   (:WRITE-EA 4
    "This value indicates the right to write or change the extended attributes of the directory.")
   (:TRAVERSE 5
    "This value indicates the right to traverse this directory if the server enforces traversal checking.")
   (:DELETE-CHILD 6
    "This value indicates the right to delete the files and directories within this directory.")
   (:READ-ATTRIBUTES 7
    "This value indicates the right to read the attributes of the directory.")
   (:WRITE-ATTRIBUTES 8
    "This value indicates the right to change the attributes of the directory.")
   (:DELETE 16
    "This value indicates the right to delete the directory.")
   (:READ-CONTROL 17
    "This value indicates the right to read the security descriptor for the directory.")
   (:WRITE-DAC 18
    "This value indicates the right to change the DACL in the security descriptor for the directory. For the DACL data structure, see ACL in [MS-DTYP].")
   (:WRITE-OWNER 19
    "This value indicates the right to change the owner in the security descriptor for the directory.")
   (:SYNCHRONIZE 20
    "SMB2 clients set this flag to any value.<43> SMB2 servers SHOULD<44> ignore this flag.")
   (:ACCESS-SYSTEM-SECURITY 24
    "This value indicates the right to read or change the SACL in the security descriptor for the directory. For the SACL data structure, see ACL in [MS-DTYP].")
   (:MAXIMUM-ALLOWED 25
    "This value indicates that the client is requesting an open to the directory with the highest level of access the client has on this directory. If no access is granted for the client on this directory, the server MUST fail the open with STATUS_ACCESS_DENIED.")
   (:GENERIC-ALL 28
    "This value indicates a request for all the access flags that are listed above except MAXIMUM_ALLOWED and ACCESS_SYSTEM_SECURITY.")
   (:GENERIC-EXECUTE 29
    "This value indicates a request for the following access flags listed above: FILE_READ_ATTRIBUTES| FILE_TRAVERSE| SYNCHRONIZE| READ_CONTROL.")
   (:GENERIC-WRITE 30
    "This value indicates a request for the following access flags listed above: FILE_ADD_FILE| FILE_ADD_SUBDIRECTORY| FILE_WRITE_ATTRIBUTES| FILE_WRITE_EA| SYNCHRONIZE| READ_CONTROL.")
   (:GENERIC-READ 31
    "This value indicates a request for the following access flags listed above: FILE_LIST_DIRECTORY| FILE_READ_ATTRIBUTES| FILE_READ_EA| SYNCHRONIZE| READ_CONTROL.")))


;; need to put this before the create-context request values because some of them need it
;; 2.2.14.1 SMB2_FILEID http://msdn.microsoft.com/en-us/library/cc246513.aspx
(defpacket smb2-file-id 
  ((persistent (:uint8 8) :initform nil :initarg :persistent)
   (volatile (:uint8 8) :initform nil :initarg :volatile))
  (:packing 1))


;; 2.2.13.2 SMB2_CREATE_CONTEXT Request Values http://msdn.microsoft.com/en-us/library/cc246504.aspx
(defpacket create-context 
  ((next :uint32 :initform 0 :initarg :next)
   (name-offset :uint16 :initform 0 :initarg :name-offset)
   (name-length :uint16 :initform 0 :initarg :name-length)
   (reserved :uint16 :initform 0)
   (data-offset :uint16 :initform 0 :initarg :data-offset)
   (data-length :uint16 :initform 0 :initarg :data-length)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; FIXME: create context buffer types
;; 2.2.13.2.1 SMB2_CREATE_EA_BUFFER http://msdn.microsoft.com/en-us/library/cc246505.aspx
;; 2.4.15 FileFullEaInformation http://msdn.microsoft.com/en-us/library/cc232069.aspx
(defpacket file-full-ea-information 
  ((next-offset :uint32 :initform 0)
   (flags :uint8 :initform 0)
   (name-length :uint8 :initform 0 :initarg :name-length)
   (value-length :uint16 :initform 0 :initarg :value-length)
   (name (:uint8 0) :initform nil)
   (value (:uint8 0) :initform nil))
  (:packing 1))

;; 2.2.13.2.2 SMB2_CREATE_SD_BUFFER http://msdn.microsoft.com/en-us/library/cc246506.aspx
;; security descriptor, as handled by ms-dtyp

;; 2.2.13.2.3 SMB2_CREATE_DURABLE_HANDLE_REQUEST http://msdn.microsoft.com/en-us/library/cc246507.aspx
(defpacket create-durable-handle-request
  ((durable-request (:uint8 16) :initform nil))
  (:packing 1))

;; 2.2.13.2.4 SMB2_CREATE_DURABLE_HANDLE_RECONNECT http://msdn.microsoft.com/en-us/library/cc246508.aspx
;; an smb2-file-id structur

;; 2.2.13.2.5 SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST http://msdn.microsoft.com/en-us/library/cc246510.aspx
;; a 8-byte timestamp (FILETIME)

;; 2.2.13.2.6 SMB2_CREATE_ALLOCATION_SIZE http://msdn.microsoft.com/en-us/library/cc246509.aspx
(defpacket smb2-create-allocation-size 
  ((size (:uint8 8) :initform nil))
  (:packing 1))

;; 2.2.13.2.7 SMB2_CREATE_TIMEWARP_TOKEN http://msdn.microsoft.com/en-us/library/cc246511.aspx
;; FILETIME timestamp

;; 2.2.13.2.8 SMB2_CREATE_REQUEST_LEASE http://msdn.microsoft.com/en-us/library/dd350266.aspx
(defpacket smb2-create-request-lease
  ((lease-key (:uint8 16) :initform nil :initarg :lease-key)
   (lease-state :uint32 :initform 0)
   (lease-flags :uint32 :initform 0)
   (lease-duration :uint64 :initform 0))
  (:packing 1))

;; 2.2.13.2.9 SMB2_CREATE_QUERY_ON_DISK_ID http://msdn.microsoft.com/en-us/library/cc246522.aspx
;; empty

;; 2.2.13.2.10 SMB2_CREATE_REQUEST_LEASE_V2 http://msdn.microsoft.com/en-us/library/hh536407.aspx
(defpacket smb2-create-request-lease-v2
  ((lease-key (:uint8 16) :initform nil :initarg :lease-key)
   (lease-state :uint32 :initform 0)
   (lease-flags :uint32 :initform 0)
   (lease-duration :uint64 :initform 0)
   (parent-lease-key (:uint8 16) :initform nil)
   (epoch :uint16 :initform 0)
   (reserved :uint16 :initform 0))
  (:packing 1))

;; 2.2.13.2.11 SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 http://msdn.microsoft.com/en-us/library/hh553782.aspx
(defpacket smb2-create-durable-handle-request-v2
  ((timeout :uint32 :initform 0)
   (flags :uint32 :initform 0)
   (reserved (:uint8 8) :initform nil)
   (create-guid ms-dtyp:guid :initform nil))
  (:packing 1))

;; 2.2.13.2.12 SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 http://msdn.microsoft.com/en-us/library/hh553994.aspx
(defpacket smb2-create-durable-handle-reconnect-v2 
  ((file-id smb2-file-id :initform nil)
   (create-guid ms-dtyp:guid :initform nil)
   (flags :uint32 :initform 0))
  (:packing 1))

;; 2.2.13.2.13 SMB2_CREATE_APP_INSTANCE_ID http://msdn.microsoft.com/en-us/library/hh536290.aspx
(defpacket smb2-create-app-instance-id 
  ((size :uint16 :initform 20)
   (reserved :uint16 :initform 0)
   (app-instance-id (:uint8 16) :initform nil))
  (:packing 1))

;; 2.2.13.2.14 SVHDX_OPEN_DEVICE_CONTEXT http://msdn.microsoft.com/en-us/library/dn364932.aspx
;; 2.2.4.12 SVHDX_OPEN_DEVICE_CONTEXT Structure http://msdn.microsoft.com/en-us/library/dn365606.aspx
(defpacket svhdx-open-device-context 
  ((version :uint32 :initform 0)
   (has-initiator-id :bool :initform nil)
   (reserved (:uint8 3) :initform nil)
   (initiator-id (:uint8 16) :initform nil)
   (flags :uint32 :initform 0)
   (originator-flags :uint32 :initform 0)
   (open-request-id :uint64 :initform 0)
   (initiator-name-length :uint16 :initform 0)
   (initiator-host-name (:wstring 64) :initform ""))
  (:packing 1))







;; 2.2.14 SMB2 CREATE Response http://msdn.microsoft.com/en-us/library/cc246512.aspx
(defpacket create-response 
  ((structure-size :uint16 :initform 89)
   (oplock-level :uint8 :initform 0 :initarg :oplock-level)
   (flags :uint8 :initform 0 :initarg :flags)
   (create-action :uint32 :initform 0 :initarg :create-action)
   (creation-time :uint64 :initform 0 :initarg :creation-time)
   (last-access-time :uint64 :initform 0 :initarg :last-access-time)
   (last-write-time :uint64 :initform 0 :initarg :last-write-time)
   (change-time :uint64 :initform 0 :initarg :change-time)
   (end-of-file :uint64 :initform 0 :initarg :end-of-file)
   (file-attributes :uint32 :initform 0 :initarg :file-attributes)
   (reserved2 :uint32 :initform 0)
   (file-id smb2-file-id :initform nil :initarg :file-id)
   (create-contexts-offset :uint32 :initform 0 :initarg :create-contexts-offset)
   (create-contexts-length :uint32 :initform 0 :initarg :create-contexts-length)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; FIXME: response context buffer types 
          
   
;; 2.2.15 SMB2 CLOSE Request http://msdn.microsoft.com/en-us/library/cc246523.aspx
(defpacket close-request 
  ((structure-size :uint16 :initform 24)
   (flags :uint16 :initform 0 :initarg :flags)
   (reserved :uint32 :initform 0)
   (file-id smb2-file-id :initform nil :initarg :file-id))
  (:packing 1))

(defflags *close-request-flags*
  ((:POSTQUERY-ATTRIB 0
    "If set, the server MUST set the attribute fields in the response, as specified in section 2.2.16, to valid values. If not set, the client MUST NOT use the values that are returned in the response.")))

;; 2.2.16 SMB2 CLOSE Response http://msdn.microsoft.com/en-us/library/cc246524.aspx
(defpacket close-response 
  ((structure-size :uint16 :initform 60)
   (flags :uint16 :initform 0 :initarg :flags)
   (reserved :uint32 :initform 0)
   (creation-time :uint64 :initform 0 :initarg :creation-time)
   (last-access-time :uint64 :initform 0 :initarg :last-access-time)
   (last-write-time :uint64 :initform 0 :initarg :last-write-time)
   (change-time :uint64 :initform 0 :initarg :change-time)
   (allocation-size :uint64 :initform 0 :initarg :allocation-size)
   (end-of-file :uint64 :initform 0 :initarg :end-of-file)
   (file-attributes :uint32 :initform 0 :initarg :file-attributes))
  (:packing 1))

;; 2.2.17 SMB2 FLUSH Request http://msdn.microsoft.com/en-us/library/cc246525.aspx
(defpacket flush-request 
  ((structure-size :uint16 :initform 24)
   (reserved :uint16 :initform 0)
   (reserved2 :uint32 :initform 0)
   (file-id smb2-file-id :initform nil :initarg :file-id))
  (:packing 1))

;; 2.2.18 SMB2 FLUSH Response http://msdn.microsoft.com/en-us/library/cc246526.aspx
(defpacket flush-response 
  ((structure-size :uint16 :initform 4)
   (reserved :uint16 :initform 0))
  (:packing 1))

;; 2.2.19 SMB2 READ Request http://msdn.microsoft.com/en-us/library/cc246527.aspx
(defpacket read-request 
  ((structure-size :uint16 :initform 49)
   (padding :uint8 :initform 0 :initarg :padding)
   (flags :uint8 :initform 0 :initarg :flags)
   (length :uint32 :initform 0 :initarg :length)
   (offset :uint64 :initform 0 :initarg :offset)
   (file-id smb2-file-id :initform nil :initarg :file-id)
   (minimum-count :uint32 :initform 0 :initarg :minumum-count)
   (channel :uint32 :initform 0 :initarg :channel)
   (remaining-bytes :uint32 :initform 0 :initarg :remaining-bytes)
   (read-channel-info-offset :uint16 :initform 0 :initarg :read-channel-info-offset)
   (read-channel-info-length :uint16 :initform 0 :initarg :read-channel-info-length)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

(defflags *read-request-channel*
  ((:NONE #x00000000
    "No channel information is present in the request. The ReadChannelInfoOffset and ReadChannelInfoLength fields MUST be set to 0 by the client and MUST be ignored by the server.")
   (:RDMA-V1 #x00000001
    "One or more SMB_DIRECT_BUFFER_DESCRIPTOR_V1 structures as specified in [MS-SMBD] section 2.2.3.1 are present in the channel information specified by ReadChannelInfoOffset and ReadChannelInfoLength fields.")
   (:RDMA-V1-INVALIDATE #x00000002
    "This value is valid only for the SMB 3.02 dialect. One or more SMB_DIRECT_BUFFER_DESCRIPTOR_V1 structures, as specified in [MS-SMBD] section 2.2.3.1, are present in the channel information specified by the ReadChannelInfoOffset and ReadChannelInfoLength fields. The server is requested to perform remote invalidation when responding to the request as specified in [MS-SMBD] section 3.1.4.2.")))



;; 2.2.20 SMB2 READ Response http://msdn.microsoft.com/en-us/library/cc246531.aspx
(defpacket read-response 
  ((structure-size :uint16 :initform 17)
   (data-offset :uint8 :initform 0 :initarg :data-offset)
   (reserved :uint8 :initform 0)
   (data-length :uint32 :initform 0 :initarg :data-length)
   (data-remaining :uint32 :initform 0 :initarg :data-remaining)
   (reserved2 :uint16 :initform 0)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.21 SMB2 WRITE Request http://msdn.microsoft.com/en-us/library/cc246532.aspx
(defpacket write-request 
  ((structure-size :uint16 :initform 49)
   (data-offset :uint16 :initform 0 :initarg :data-offset)
   (length :uint32 :initform 0 :initarg :length)
   (offset :uint64 :initform 0 :initarg :offset)
   (file-id smb2-file-id :initform nil :initarg :file-id)
   (channel :uint32 :initform 0 :initarg :channel)
   (remaining-bytes :uint32 :initform 0 :initarg :remaining-bytes)
   (write-channel-info-offset :uint16 :initform 0 :initarg :write-channel-info-offset)
   (write-channel-info-length :uint16 :initform 0 :initarg :write-channel-info-length)
   (flags :uint32 :initform 0 :initarg :flags)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.22 SMB2 WRITE Response http://msdn.microsoft.com/en-us/library/cc246533.aspx
(defpacket write-response 
  ((structure-size :uint16 :initform 17)
   (reserved :uint16 :initform 0)
   (count :uint32 :initform 0 :initarg :count)
   (remaining :uint32 :initform 0 :initarg :remaining)
   (write-channel-info-offset :uint16 :initform 0 :initarg :write-channel-info-offset)
   (write-channel-info-length :uint16 :initform 0 :initarg :write-channel-info-length))
  (:packing 1))


;; 2.2.23.1 Oplock Break Notification http://msdn.microsoft.com/en-us/library/dd357793.aspx
(defpacket oplock-break-notification
  ((structure-size :uint16 :initform 24)
   (oplock-level :uint8 :initform 0 :initarg :oplock-level)
   (reserved :uint8 :initform 0)
   (reserved2 :uint32 :initform 0)
   (file-id smb2-file-id :initform nil :initarg :file-id))
  (:packing 1))

;; 2.2.23.2 Lease Break Notification http://msdn.microsoft.com/en-us/library/dd304200.aspx
(defpacket lease-break-notification 
  ((structure-size :uint16 :initform 44)
   (new-epoch :uint16 :initform 0 :initarg :new-epoch)
   (flags :uint32 :initform 0 :initarg :flags)
   (lease-key :uint16 :initform 0 :initarg :lease-key)
   (current-lease-state :uint32 :initform 0 :initarg :current-lease-state)
   (new-lease-state :uint32 :initform 0 :initarg :new-lease-state)
   (break-reason :uint32 :initform 0)
   (access-mask-hint :uint32 :initform 0)
   (share-mask-hint :uint32 :initform 0))
  (:packing 1))

(defflags *lease-break-flags* 
  ((:ACK-REQUIRED #x01
    "A Lease Break Acknowledgment is required.")))

;; 2.2.24.1 Oplock Break Acknowledgment http://msdn.microsoft.com/en-us/library/dd357663.aspx
(defpacket oplock-break-ack
  ((structure-size :uint16 :initform 24)
   (oplock-level :uint8 :initform 0 :initarg :oplock-level)
   (reserved :uint8 :initform 0)
   (reserved2 :uint32 :initform 0)
   (file-id smb2-file-id :initform nil :initarg :file-id))
  (:packing 1))

;; 2.2.24.2 Lease Break Acknowledgment http://msdn.microsoft.com/en-us/library/dd356522.aspx
(defpacket lease-break-ack
  ((structure-size :uint16 :initform 36)
   (reserved :uint16 :initform 0)
   (flags :uint32 :initform 0)
   (lease-key :uint16 :initform 0)
   (lease-state :uint32 :initform 0 :initarg :lease-state)
   (lease-duration :uint64 :initform 0))
  (:packing 1))

(defenum *lease-state*
  ((:NONE #x00
    "No lease is granted.")
   (:READ-CACHING #x01
    "A read caching lease is accepted.")
   (:HANDLE-CACHING #x02
    "A handle caching lease is accepted.")
   (:WRITE-CACHING #x04
    "A write caching lease is accepted.")))


;; 2.2.25.1 Oplock Break Response http://msdn.microsoft.com/en-us/library/dd304510.aspx
(defpacket oplock-break-response 
  ((structure-size :uint16 :initform 24)
   (oplock-level :uint8 :initform 0 :initarg :oplock-level)
   (reserved :uint8 :initform 0)
   (reserved2 :uint32 :initform 0)
   (file-id smb2-file-id :initform nil :initarg :file-id))
  (:packing 1))

;; 2.2.25.2 Lease Break Response http://msdn.microsoft.com/en-us/library/dd304237.aspx
(defpacket lease-break-response 
  ((structure-size :uint16 :initform 36)
   (reserved :uint16 :initform 0)
   (flags :uint32 :initform 0)
   (lease-key :uint16 :initform 0 :initarg :lease-key)
   (lease-state :uint32 :initform 0 :initarg :lease-state)
   (lease-duration :uint64 :initform 0))
  (:packing 1))

;; 2.2.26.1 SMB2_LOCK_ELEMENT Structure http://msdn.microsoft.com/en-us/library/cc246538.aspx
(defpacket lock-element 
  ((offset :uint64 :initform 0 :initarg :offset)
   (length :uint64 :initform 0 :initarg :length)
   (flags :uint32 :initform 0 :initarg :flags)
   (reserved :uint32 :initform 0))
  (:packing 1))

(defflags *lock-flags*
  ((:SHARED-LOCK 0
    "The range MUST be locked shared, allowing other opens to read from or take a shared lock on the range. All opens MUST NOT be allowed to write within the range. Other locks can be requested and taken on this range.")
   (:EXCLUSIVE-LOCK 1
    "The range MUST be locked exclusive, not allowing other opens to read, write, or lock within the range.")
   (:UNLOCK 2
    "The range MUST be unlocked from a previous lock taken on this range. The unlock range MUST be identical to the lock range. Sub-ranges cannot be unlocked.")
   (:FAIL-IMMEDIATELY 4
    "The lock operation MUST fail immediately if it conflicts with an existing lock, instead of waiting for the range to become available.")))

;; 2.2.26 SMB2 LOCK Request http://msdn.microsoft.com/en-us/library/cc246537.aspx
(defpacket lock-request 
  ((structure-size :uint16 :initform 48)
   (lock-count :uint16 :initform 0 :initarg :lock-count)
   (lock-sequence :uint32 :initform 0 :initarg :lock-sequence)
   (file-id smb2-file-id :initform nil :initarg :file-id)
   ;; payload
   (locks (lock-element 0) :initform nil :accessor packet-buffer))
  (:packing 1))


;; 2.2.27 SMB2 LOCK Response http://msdn.microsoft.com/en-us/library/cc246539.aspx
(defpacket lock-response 
  ((structure-size :uint16 :initform 4)
   (reserved :uint16 :initform 0))
  (:packing 1))

;; 2.2.28 SMB2 ECHO Request http://msdn.microsoft.com/en-us/library/cc246540.aspx
(defpacket echo-request 
  ((strucutre-size :uint16 :initform 4)
   (reserved :uint16 :initform 0))
  (:packing 1))

;; 2.2.29 SMB2 ECHO Response http://msdn.microsoft.com/en-us/library/cc246541.aspx
(defpacket echo-response
  ((strucutre-size :uint16 :initform 4)
   (reserved :uint16 :initform 0))
  (:packing 1))

;; 2.2.30 SMB2 CANCEL Request http://msdn.microsoft.com/en-us/library/cc246544.aspx
(defpacket cancel-request 
  ((strucutre-size :uint16 :initform 4)
   (reserved :uint16 :initform 0))
  (:packing 1))

;; 2.2.31 SMB2 IOCTL Request http://msdn.microsoft.com/en-us/library/cc246545.aspx
(defpacket ioctl-request 
  ((structure-size :uint16 :initform 57)
   (reserved :uint16 :initform 0)
   (ctl-code :uint32 :initform 0 :initarg :ctl-code)
   (file-id smb2-file-id :initform nil :initarg :file-id)
   (input-offset :uint32 :initform 0 :initarg :input-offset)
   (input-count :uint32 :initform 0 :initarg :input-count)
   (max-input-response :uint32 :initform 0 :initarg :max-input-response)
   (output-offset :uint32 :initform 0 :initarg :output-offset)
   (output-count :uint32 :initform 0 :initarg :ouput-count)
   (max-output-response :uint32 :initform 0 :initarg :max-output-response)
   (flags :uint32 :initform 0 :initarg :flags)
   (reserved2 :uint32 :initform 0)
   ;; payload
   (buffer (:uint8 0) :initform nil :initarg :buffer :accessor packet-buffer))
  (:packing 1))

(defenum *ctl-codes*
  ((:DFS-GET-REFERRALS #x00060194)
   (:PIPE-PEEK #x0011400C)
   (:PIPE-WAIT #x00110018)
   (:PIPE-TRANSCEIVE #x0011C017)
   (:SRV-COPYCHUNK #x001440F2)
   (:SRV-ENUMERATE-SNAPSHOTS #x00144064)
   (:SRV-REQUEST-RESUME-KEY #x00140078)
   (:SRV-READ-HASH #x001441bb)
   (:SRV-COPYCHUNK-WRITE #x001480F2)
   (:LMR-REQUEST-RESILIENCY #x001401D4)
   (:QUERY-NETWORK-INTERFACE-INFO #x001401FC)
   (:SET-REPARSE-POINT #x000900A4)
   (:DFS-GET-REFERRALS-EX #x000601B0)
   (:FILE-LEVEL-TRIM #x00098208)
   (:VALIDATE-NEGOTIATE-INFO #x00140204)))

;; 2.2.31.1.1 SRV_COPYCHUNK http://msdn.microsoft.com/en-us/library/cc246546.aspx
(defpacket srv-copychunk
  ((source-offset :uint64 :initform 0 :initarg :source-offset)
   (target-offset :uint64 :initform 0 :initarg :target-offset)
   (length :uint32 :initform 0 :initarg :length)
   (reserved :uint32 :initform 0))
  (:packing 1))

;; 2.2.31.1 SRV_COPYCHUNK_COPY http://msdn.microsoft.com/en-us/library/cc246547.aspx
(defpacket srv-copychunk-copy
  ((source-key (:uint8 24) :initform nil :initarg :source-key)
   (chunk-count :uint32 :initform 0 :initarg :chunk-count)
   (reserved :uint32 :initform 0)
   ;; payload
   (chunks (srv-copychunk 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.31.2 SRV_READ_HASH Request http://msdn.microsoft.com/en-us/library/dd350338.aspx
(defenum *hash-type* 
  ((:PEER-DIST #x00000001
    "Indicates the hash is requested for branch caching as described in [MS-PCCRC].")))

(defpacket srv-read-hash
  ((hash-type :uint32 :initform (enum :peer-dist *hash-type*) :initarg :hash-type)
   (hash-version :uint32 :initform 0 :initarg :hash-version)
   (hash-retrieval-type :uint32 :initform 0 :initarg :hash-retrieval-type)
   (length :uint32 :initform 0 :initarg :length)
   (offset :uint64 :initform 0 :initarg :offset))
  (:packing 1))

(defenum *hash-version*
  ((:VER_1 #x00000001
    "Branch cache version 1.")
   (:VER_2 #x00000002
     "Branch cache version 2. This value is only applicable for the SMB 3.x dialect family.")))

(defenum *hash-retrieval-type*
  ((:HASH-BASED #x00000001
    "The Offset field in the SRV_READ_HASH request is relative to the beginning of the Content Information File.")
   (:FILE-BASED #x00000002
    "The Offset field in the SRV_READ_HASH request is relative to the beginning of the file indicated by the FileId field in the IOCTL request. This value is only applicable for the SMB 3.x dialect family.")))


;; 2.2.31.3 NETWORK_RESILIENCY_REQUEST Request http://msdn.microsoft.com/en-us/library/ee379824.aspx
(defpacket network-resiliency-request 
  ((timeout :uint32 :initform 0 :initarg :timeout)
   (reserved :uint32 :initform 0))
  (:packing 1))

;; 2.2.31.4 VALIDATE_NEGOTIATE_INFO Request http://msdn.microsoft.com/en-us/library/hh880558.aspx
(defpacket validate-negotiate-info-request
  ((capabilities :uint32 :initform 0 :initarg :capabilities)
   (guid (:uint8 16) :initform nil :initarg :guid)
   (security-mode :uint16 :initform 0 :initarg :security-mode)
   (dialect-count :uint16 :initform 0 :initarg :dialect-count)
   ;; payload
   (dialects (:uint16 0) :initform nil :initarg :dialects :accessor packet-buffer))
  (:packing 1))

;; 2.2.32 SMB2 IOCTL Response http://msdn.microsoft.com/en-us/library/cc246548.aspx
(defpacket ioctl-response 
  ((structure-size :uint16 :initform 49)
   (reserved :uint16 :initform 0)
   (ctl-code :uint32 :initform 0 :initarg :ctl-code)
   (file-id smb2-file-id :initform nil :initarg :file-id)
   (input-offset :uint32 :initform 0 :initarg :input-offset)
   (input-count :uint32 :initform 0 :initarg :input-count)
   (output-offset :uint32 :initform 0 :initarg :output-offset)
   (output-count :uint32 :initform 0 :initarg :output-count)
   (flags :uint32 :initform 0)
   (reserved2 :uint32 :initform 0)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.32.1 SRV_COPYCHUNK_RESPONSE http://msdn.microsoft.com/en-us/library/cc246549.aspx
(defpacket srv-copychunk-response
  ((chunks-written :uint32 :initform 0 :initarg :chunks-written)
   (chunk-bytes-written :uint32 :initform 0 :initarg :chunk-bytes-written)
   (total-bytes-written :uint32 :initform 0 :initarg :total-bytes-written))
  (:packing 1))

;; 2.2.32.2 SRV_SNAPSHOT_ARRAY http://msdn.microsoft.com/en-us/library/cc246550.aspx
(defpacket srv-snapshot-array 
  ((number-of-snapshots :uint32 :initform 0 :initarg :number-of-snapshots)
   (number-of-snapshots-returned :uint32 :initform 0 :initarg :number-of-snapshots-returned)
   (snapshot-array-size :uint32 :initform 0 :initarg :snapshot-array-size)
   ;; payload
   (snapshots (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.32.3 SRV_REQUEST_RESUME_KEY Response http://msdn.microsoft.com/en-us/library/cc246804.aspx
(defpacket srv-request-resume-key 
  ((resume-key (:uint8 24) :initform nil :initarg :resume-key)
   (context-length :uint32 :initform 0)
   ;; payload
   (context (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.32.4.1 HASH_HEADER http://msdn.microsoft.com/en-us/library/dd976907.aspx
(defpacket hash-header 
  ((hash-type :uint32 :initform 1)
   (hash-version :uint32 :initform 0 :initarg :hash-version)
   (source-file-change-time :uint64 :initform 0 :initarg :source-file-change-time)
   (source-file-size :uint64 :initform 0 :initarg :source-file-size)
   (hash-blob-length :uint32 :initform 0 :initarg :hash-blob-length)
   (hash-blob-offset :uint32 :initform 0 :initarg :hash-blob-offset)
   (dirty :uint16 :initform 0 :initarg :dirty)
   (source-file-name-length :uint16 :initform 0 :initarg :source-file-name-length)
   ;; payload
   (source-file-name (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.32.4.2 SRV_HASH_RETRIEVE_HASH_BASED http://msdn.microsoft.com/en-us/library/hh553938.aspx
(defpacket srv-hash-retrieve-hash-based 
  ((offset :uint64 :initform 0 :initarg :offset)
   (buffer-length :uint32 :initform 0 :initarg :buffer-length)
   (reserved :uint32 :initform 0)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.32.4.3 SRV_HASH_RETRIEVE_FILE_BASED http://msdn.microsoft.com/en-us/library/hh553953.aspx
(defpacket srv-hash-retrieve-file-based 
  ((file-data-offset :uint64 :initform 0 :initarg :file-data-offset)
   (file-data-length :uint64 :initform 0 :initarg :file-data-length)
   (buffer-length :uint32 :initform 0 :initarg :buffer-length)
   (reserved :uint32 :initform 0)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.32.5.1 SOCKADDR_STORAGE http://msdn.microsoft.com/en-us/library/jj665641.aspx
(defpacket sockaddr-storage 
  ((family :uint16 :initform 0 :initarg :family)
   ;; payload 
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.32.5.1.1 SOCKADDR_IN http://msdn.microsoft.com/en-us/library/jj678981.aspx
(defpacket sockaddr-in 
  ((port :uint16 :initform 0 :initarg :port)
   (ipv4-address :uint32 :initform 0 :initarg :ipv4-address)
   (reserved :uint64 :initform 0))
  (:packing 1))

;; 2.2.32.5.1.2 SOCKADDR_IN6 http://msdn.microsoft.com/en-us/library/jj678848.aspx
(defpacket sockaddr-in6 
  ((port :uint16 :initform 0 :initarg :port)
   (flow-info :uint32 :initform 0)
   (ipv6-address (:uint8 16) :initform nil :initarg :ipv6-address)
   (scope-id :uint32 :initform 0))
  (:packing 1))

;; 2.2.32.5 NETWORK_INTERFACE_INFO Response http://msdn.microsoft.com/en-us/library/hh536505.aspx
(defpacket network-interface-info 
  ((next :uint32 :initform 0 :initarg :next)
   (if-index :uint32 :initform 0 :initarg :if-index)
   (capability :uint32 :initform 0 :initarg :capability)
   (reserved :uint32 :initform 0)
   (link-speed :uint64 :initform 0 :initarg :link-speed)
   (sockaddr sockaddr-storage :initform nil))
  (:packing 1))

;; 2.2.32.6 VALIDATE_NEGOTIATE_INFO Response http://msdn.microsoft.com/en-us/library/hh880693.aspx
(defpacket validate-negotiate-info-response 
  ((capabilities :uint32 :initform 0 :initarg :capabilities)
   (guid (:uint8 16) :initform nil :initarg :guid)
   (security-mode :uint16 :initform 0 :initarg :security-mode)
   (dialect :uint16 :initform 0 :initarg :dialect))
  (:packing 1))

;; 2.2.33 SMB2 QUERY_DIRECTORY Request http://msdn.microsoft.com/en-us/library/cc246551.aspx
(defpacket query-directory-request 
  ((structure-size :uint16 :initform 33)
   (file-information :uint8 :initform 0 :initarg :file-information)
   (flags :uint8 :initform 0 :initarg :flags)
   (file-index :uint32 :initform 0 :initarg :file-index)
   (file-id smb2-file-id :initform nil :initarg :file-id)
   (file-name-offset :uint16 :initform 0 :initarg :file-name-offset)
   (file-name-length :uint16 :initform 0 :initarg :file-name-length)
   (output-buffer-length :uint32 :initform 0 :initarg :output-buffer-length)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.34 SMB2 QUERY_DIRECTORY Response http://msdn.microsoft.com/en-us/library/cc246552.aspx
(defpacket query-directory-response 
  ((structure-size :uint16 :initform 9)
   (output-buffer-offset :uint16 :initform 0 :initarg :output-buffer-offset)
   (output-buffer-length :uint16 :initform 0 :initarg :output-buffer-length)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.35 SMB2 CHANGE_NOTIFY Request http://msdn.microsoft.com/en-us/library/cc246553.aspx
(defpacket change-notify-request 
  ((structure-size :uint16 :initform 32)
   (flags :uint16 :initform 1 :initarg :flags)
   (output-buffer-length :uint32 :initform 0 :initarg :output-buffer-length)
   (file-id smb2-file-id :initform nil :initarg :file-id)
   (completion-filter :uint32 :initform 0 :initarg :completion-filter)
   (reserved :uint32 :initform 0))
  (:packing 1))


(defflags *completion-filter-flags*
  ((:FILE-NAME 0
    "The client is notified if a file-name changes.")
   (:DIR-NAME 1
    "The client is notified if a directory name changes.")
   (:ATTRIBUTES 2
    "The client is notified if a file's attributes change. Possible file attribute values are specified in [MS-FSCC] section 2.6.")
   (:SIZE 3
    "The client is notified if a file's size changes.")
   (:LAST-WRITE 4
    "The client is notified if the last write time of a file changes.")
   (:LAST-ACCESS 5
    "The client is notified if the last access time of a file changes.")
   (:CREATION 6
    "The client is notified if the creation time of a file changes.")
   (:EA 7
    "The client is notified if a file's extended attributes (EAs) change.")
   (:SECURITY 8
    "The client is notified of a file's access control list (ACL) settings change.")
   (:STREAM-NAME 9
    "The client is notified if a named stream is added to a file.")
   (:STREAM-SIZE 10
    "The client is notified if the size of a named stream is changed.")
   (:STREAM-WRITE 11
    "The client is notified if a named stream is modified.")))

;; 2.2.36 SMB2 CHANGE_NOTIFY Response http://msdn.microsoft.com/en-us/library/cc246554.aspx
(defpacket change-notify-response 
  ((structure-size :uint16 :initform 9)
   (output-buffer-offset :uint16 :initform 0 :initarg :output-buffer-offset)
   (output-buffer-length :uint32 :initform 0 :initarg :output-buffer-length)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))


;; 2.2.37 SMB2 QUERY_INFO Request http://msdn.microsoft.com/en-us/library/cc246557.aspx
(defpacket query-info-request 
  ((structure-size :uint16 :initform 41)
   (info-type :uint8 :initform 0 :initarg :info-type)
   (file-info-class :uint8 :initform 0 :initarg :file-info-class)
   (output-buffer-length :uint32 :initform 0 :initarg :output-buffer-length)
   (input-buffer-offset :uint32 :initform 0 :initarg :input-buffer-offset)
   (reserved :uint16 :initform 0)
   (input-buffer-length :uint32 :initform 0 :initarg :input-buffer-length)
   (additional-information :uint32 :initform 0 :initarg :additional-information)
   (flags :uint32 :initform 0 :initarg :flags)
   (file-id smb2-file-id :initform nil :initarg :file-id)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

(defenum *additional-information*
  ((:OWNER-SECURITY-INFORMATION #x00000001
    "The client is querying the owner from the security descriptor of the file or named pipe.")
   (:GROUP-SECURITY-INFORMATION #x00000002
    "The client is querying the group from the  security descriptor of the file or named pipe.")
   (:DACL-SECURITY-INFORMATION #x00000004
     "The client is querying the discretionary access control list from the security descriptor of the file or named pipe.")
   (:SACL-SECURITY-INFORMATION #x00000008
    "The client is querying the system access control list from the security descriptor of the file or named pipe.")
   (:LABEL-SECURITY-INFORMATION #x00000010
    "The client is querying the integrity label from the security descriptor of the file or named pipe.")
   (:ATTRIBUTE-SECURITY-INFORMATION #x00000020
    "The client is querying the resource attribute from the security descriptor of the file or named pipe.")
   (:SCOPE-SECURITY-INFORMATION #x00000040
    "The client is querying the central access policy of the resource from the security descriptor of the file or named pipe.")
   (:BACKUP-SECURITY-INFORMATION #x00010000
    "The client is querying the security descriptor information used for backup operation.")))

(defenum *info-type*
 ((:INFO-FILE #x01
   "The file information is requested.")
  (:INFO-FILESYSTEM #x02
   "The underlying object store information is requested.")
  (:INFO-SECURITY #x03
   "The security information is requested.")
  (:INFO-QUOTA #x04
   "The underlying object store quota information is requested.")))

(defenum *file-info-class*
  ((:FileAccessInformation 8 "Query")
   (:FileAlignmentInformation 17 "Query")
   (:FileAllInformation 18 "Query")
   (:FileAllocationInformation 19 "Set")
   (:FileAlternateNameInformation 21 "Query")
   (:FileAttributeTagInformation 35 "Query")
   (:FileBasicInformation 4 "Query, Set")
   (:FileBothDirectoryInformation 3 "Query")
   (:FileCompressionInformation 28 "Query")
   (:FileDirectoryInformation 1 "Query")
   (:FileDispositionInformation 13 "Set")
   (:FileEaInformation 7 "Query")
   (:FileEndOfFileInformation 20 "Set")
   (:FileFullDirectoryInformation 2 "Query")
   (:FileFullEaInformation 15 "Query, Set")
   (:FileHardLinkInformation 46 "LOCAL")
   (:FileIdBothDirectoryInformation 37 "Query")
   (:FileIdFullDirectoryInformation 38 "Query")
   (:FileFullEaInformation 15 "Query, Set")
   (:FileHardLinkInformation 46 "LOCAL")
   (:FileIdBothDirectoryInformation 37 "Query")
   (:FileIdFullDirectoryInformation 38 "Query")
   (:FileIdGlobalTxDirectoryInformation 50 "LOCAL")
   (:FileInternalInformation 6 "Query")
   (:FileLinkInformation 11 "Set")
   (:FileMailslotQueryInformation 26 "LOCAL")
   (:FileMailslotSetInformation 27 "LOCAL")
   (:FileModeInformation 16 "Query, Set")
   (:FileMoveClusterInformation 31 "<76>")
   (:FileNameInformation 9 "LOCAL")
   (:FileNamesInformation  12 "Query")
   (:FileNetworkOpenInformation 34 "Query")
   (:FileNormalizedNameInformation 48 "<78>")
   (:FileObjectIdInformation 29 "LOCAL<79>")
   (:FilePipeInformation 23 "Query, Set")
   (:FilePipeLocalInformation 24 "Query")
   (:FilePipeRemoteInformation 25 "Query")
   (:FilePositionInformation 14 "Query, Set")
   (:FileQuotaInformation 32 "Query, Set<80>")
   (:FileRenameInformation  10 "Set")
   (:FileReparsePointInformation 33 "LOCAL<81>")
   (:FileSfioReserveInformation 44 "LOCAL<82>")
   (:FileSfioVolumeInformation 45 "<83>")
   (:FileShortNameInformation 40 "Set")
   (:FileStandardInformation 5 "Query")
   (:FileStandardLinkInformation 54 "LOCAL<84>")
   (:FileStreamInformation 22 "Query")
   (:FileTrackingInformation 36 "LOCAL<85>")
   (:FileValidDataLengthInformation 39 "Set")))


;; 2.2.37.1 SMB2_QUERY_QUOTA_INFO http://msdn.microsoft.com/en-us/library/cc246558.aspx
(defpacket query-quota-info 
  ((return-single :uint8 :initform 0 :initarg :return-single)
   (restart-scan :uint8 :initform 0 :initarg :restart-scan)
   (reserved :uint16 :initform 0)
   (sid-list-length :uint32 :initform 0 :initarg :sid-list-length)
   (start-sid-length :uint32 :initform 0 :initarg :start-sid-length)
   (start-sid-offset :uint32 :initform 0 :initarg :start-sid-offset)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.38 SMB2 QUERY_INFO Response http://msdn.microsoft.com/en-us/library/cc246559.aspx
(defpacket query-info-response 
  ((structure-size :uint16 :initform 9)
   (output-buffer-offset :uint16 :initform 0 :initarg :output-buffer-offset)
   (output-buffer-length :uint32 :initform 0 :initarg :output-buffer-length)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.39 SMB2 SET_INFO Request http://msdn.microsoft.com/en-us/library/cc246560.aspx
(defpacket set-info-request 
  ((structure-size :uint16 :initform 33)
   (info-type :uint8 :initform 0 :initarg :info-type)
   (file-info-class :uint8 :initform 0 :initarg :file-info-class)
   (buffer-length :uint32 :initform 0 :initarg :buffer-length)
   (buffer-offset :uint16 :initform 0 :initarg :buffer-offset)
   (reserved :uint16 :initform 0)
   (additional-information :uint32 :initform 0 :initarg :additional-information)
   (file-id smb2-file-id :initform nil :initarg :file-id)
   ;; payload
   (buffer (:uint8 0) :initform nil :accessor packet-buffer))
  (:packing 1))

;; 2.2.40 SMB2 SET_INFO Response
(defpacket set-info-response 
  ((structure-size :uint16 :initform 2))
  (:packing 1))

;; 2.2.41 SMB2 TRANSFORM_HEADER http://msdn.microsoft.com/en-us/library/hh880787.aspx
(defpacket transform-header 
  ((protocol-id (:uint8 4) :initform #(253 83 77 66)) ;; #(#xfd 'S' 'M' 'B')
   (signature (:uint8 16) :initform nil :initarg :signature)
   (nonce (:uint8 16) :initform nil :initarg :nonce)
   (original-message-size :uint32 :initform 0 :initarg :original-message-size)
   (reserved :uint16 :initform 0)
   (encryption-algorithm :uint16 :initform 1 :initarg :encryption-algorithm))
  (:packing 1))

(defenum *encryption-algorithm* 
  ((:AES128-CCM #x0001
    "The message is encrypted by using the AES128 algorithm.")))






