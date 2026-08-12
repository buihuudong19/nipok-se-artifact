CREATE TABLE IF NOT EXISTS payments (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    version     INT NOT NULL DEFAULT 0,
    payment_id  VARCHAR(36) NOT NULL,
    debtor_account_id VARCHAR(36) NOT NULL,
    creditor_name     VARCHAR(255),
    creditor_account_no VARCHAR(255),
    creditor_bank_code  VARCHAR(255),
    creditor_bank_name  VARCHAR(255),
    amount      DECIMAL(19, 2) NOT NULL,
    currency    VARCHAR(10) NOT NULL,
    payment_type VARCHAR(50),
    remittance_information TEXT,
    status      VARCHAR(50),
    execution_date DATE,
    UNIQUE INDEX payments_unique_idx (debtor_account_id, payment_id)
);
