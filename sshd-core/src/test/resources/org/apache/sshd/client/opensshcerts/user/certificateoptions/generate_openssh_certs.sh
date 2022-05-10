ssh-keygen -f ./user_rsa_sha2_256_4096 -t rsa -b 4096 -N '' -C 'user_rsa_sha2_256_4096'
ssh-keygen -f ./user_rsa_sha2_512_4096 -t rsa -b 4096 -N '' -C 'user_rsa_sha2_512_4096'
ssh-keygen -f ./user_ed25519 -t ed25519 -N '' -C 'user_ed25519'
ssh-keygen -f ./user_ecdsa_256 -t ecdsa -b 256 -N '' -C 'user_ecdsa_256'
ssh-keygen -f ./user_ecdsa_384 -t ecdsa -b 384 -N '' -C 'user_ecdsa_384'
ssh-keygen -f ./user_ecdsa_521 -t ecdsa -b 521 -N '' -C 'user_ecdsa_521'

ssh-keygen -s ../../ca/ca -I user01 -n user01 -t rsa-sha2-256 -O source-address="127.0.0.1/32" -O force-command="/path/to/script.sh" user_rsa_sha2_256_4096
ssh-keygen -s ../../ca/ca -I user01 -n user01 -t rsa-sha2-512 -O source-address="127.0.0.1/32" -O force-command="/path/to/script.sh" user_rsa_sha2_512_4096
ssh-keygen -s ../../ca/ca -I user01 -n user01 -t rsa-sha2-512 -O source-address="127.0.0.1/32" -O force-command="/path/to/script.sh" user_ed25519
ssh-keygen -s ../../ca/ca -I user01 -n user01 -t rsa-sha2-512 -O source-address="127.0.0.1/32" -O force-command="/path/to/script.sh" user_ecdsa_256
ssh-keygen -s ../../ca/ca -I user01 -n user01 -t rsa-sha2-512 -O source-address="127.0.0.1/32" -O force-command="/path/to/script.sh" user_ecdsa_384
ssh-keygen -s ../../ca/ca -I user01 -n user01 -t rsa-sha2-512 -O source-address="127.0.0.1/32" -O force-command="/path/to/script.sh" user_ecdsa_521