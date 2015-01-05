

(in-package :ms-smb2)





(defun make-guid ()
  (make-array 16 :element-type '(unsigned-byte 8)
              :initial-contents
              (loop for i below 16 collect (random 256))))

(defun make-header ()
  (pack (make-instance 'header-sync 
                       :command #.(enum :create *commands*)
                       :credit-request 1
                       :credit-charge 1)
        'header-sync))

(defun make-msg ()
  (let ((msg 
         (usb8 
          (make-header)
          (pack (make-instance 'negotiate-request
                               :dialect-count 1
                               :security-mode (enum :negotiate-signing-enabled *negotiate-request-modes*))
                'negotiate-request)
          (pack #x0202 :uint16))))
    (usb8 
     (pack (make-instance 'smb-transport-header :length (length msg))
           'smb-transport-header)
     msg)))
                        
(defun send-msg (host msg)
  (let ((socket (usocket:socket-connect host 445 :element-type '(unsigned-byte 8))))
    (unwind-protect
         (let ((stream (usocket:socket-stream socket)))                          
           (write-sequence msg stream)
           (let ((theader (make-array 4 :element-type '(unsigned-byte 8))))
             (read-sequence theader stream)
             theader))
      (usocket:socket-close socket))))

(defun save-msg (msg)
  (with-open-file (f "test.dat" :direction :output :if-exists :supersede :element-type '(unsigned-byte 8))
    (write-sequence msg f))
  nil)

(defun make-msg2 ()
  (let ((msg 
         (usb8 
          (pack (make-instance 'header-sync 
                               :command (enum :create *commands*)
                               :credit-request #x7e)
                'header-sync)
          (pack (make-instance 'negotiate-request
                               :dialect-count 1
                               :security-mode (enum :negotiate-signing-enabled *negotiate-request-modes*))
                'negotiate-request)
          (pack #x0202 :uint16))))
    (usb8 
     (pack (make-instance 'smb-transport-header 
                          :length (unpack (reverse (pack (length msg) :uint24)) :uint24))
           'smb-transport-headeR)
     msg)))

(defun make-get-info-msg ()
  (pack 
   (make-instance 'query-info-request 
                  :output-buffer-length 88
                  :info-type #.(enum :info-filesystem *info-type*)
                  :file-info-class #.(enum :filedirectoryinformation *file-info-class*)
                  :file-id (make-instance 'smb2-file-id 
                                          :persistent #(#x99 1 0 0 #x20 0 0 0)
                                          :volatile #(#x45 0 0 0 #xff #xff #xff #xff)))
   'query-info-request))

(defun send-msg* (host msg)
  (send-msg host
            (usb8 (pack (make-instance 'smb-transport-header :length (length msg))
                        'smb-transport-header)
                  (pack (make-instance 'header-sync 
                                       :credit-charge 1
                                       :command #.(enum :query-info *commands*)
                                       :credit-request 1)
                        'header-sync)                                       
                  msg)))
  
