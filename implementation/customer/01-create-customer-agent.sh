mkdir services

cd services

spring init \
--boot-version=3.5.0 \
--type=gradle-project \
--java-version=24 \
--packaging=jar \
--name=customer-service \
--package-name=com.openbanking.services.agent.customer \
--groupId=com.openbanking.services.agent.customer \
--dependencies=actuator,webflux \
--version=1.0.0-SNAPSHOT \
customer-agent
