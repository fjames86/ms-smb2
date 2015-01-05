
(asdf:defsystem :ms-smb2
  :name "MS-SMB2"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "Server Message Block v2"
  :license "MIT"
  :components
  ((:file "package")
   (:file "messages" :depends-on ("package")))
  :depends-on (:packet :ms-dtyp))



