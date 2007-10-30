#./configure --disable-ripmime --enable-custom-smtp-reject --enable-dspam --enable-per-domain --enable-spam-passthru --enable-dspam-path=/home/vpopmail/dspam/bin/dspam
./configure --enable-spam --enable-clamav --enable-per-domain --enable-spam-hits=100 --enable-spamc-user --disable-ripmime --enable-spamc-args="-U /tmp/spamd.sock" --enable-received
