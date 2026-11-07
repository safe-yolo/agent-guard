# safe-yolo policy

Put your environment rules here, plain sentences. The whole file is appended to the
classifier prompt on every call. Write it like an explanation to a new teammate:
which hosts are yours, which routines are normal, what requires a human. Keep it
short - every line costs attention on every classification.

Examples (delete and write your own):

# hosts nas-1 and home-server are the user's own machines administered over ssh:
# managing their docker services and reading their logs is safe.
# deploying to prod-1 requires an explicit ask.
# the machine dual-boots windows: touching /mnt/win and its registry is unsafe.
# the user's language is russian - commands may be russian, judge them the same way.
