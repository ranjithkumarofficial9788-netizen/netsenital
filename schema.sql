-- NetSential MySQL Database Schema (MySQL 8.0+)
-- Character set: utf8mb4, Engine: InnoDB

CREATE DATABASE IF NOT EXISTS `netsential_db`
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE `netsential_db`;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(64) NOT NULL UNIQUE,
  `email` VARCHAR(120) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `role` VARCHAR(20) NOT NULL DEFAULT 'analyst',
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_users_role` (`role`),
  INDEX `idx_users_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Upload Batches Table
CREATE TABLE IF NOT EXISTS `upload_batches` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `original_filename` VARCHAR(255) NOT NULL,
  `uploaded_by` INT NULL,
  `total_rows` INT NOT NULL DEFAULT 0,
  `accepted_rows` INT NOT NULL DEFAULT 0,
  `rejected_rows` INT NOT NULL DEFAULT 0,
  `status` VARCHAR(30) NOT NULL DEFAULT 'completed',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT `fk_upload_user` FOREIGN KEY (`uploaded_by`)
    REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Security Events Table
CREATE TABLE IF NOT EXISTS `security_events` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `event_type` VARCHAR(64) NOT NULL,
  `source_ip` VARCHAR(45) NOT NULL,
  `username` VARCHAR(64) NULL,
  `status` VARCHAR(30) NOT NULL DEFAULT 'failure',
  `severity` VARCHAR(20) NOT NULL,
  `message` TEXT NOT NULL,
  `event_time` DATETIME NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `upload_batch_id` INT NULL,
  INDEX `idx_events_type` (`event_type`),
  INDEX `idx_events_source_ip` (`source_ip`),
  INDEX `idx_events_username` (`username`),
  INDEX `idx_events_severity` (`severity`),
  INDEX `idx_events_time` (`event_time`),
  INDEX `idx_events_batch` (`upload_batch_id`),
  CONSTRAINT `fk_events_batch` FOREIGN KEY (`upload_batch_id`)
    REFERENCES `upload_batches` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Alerts Table
CREATE TABLE IF NOT EXISTS `alerts` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `event_id` INT NOT NULL,
  `rule_code` VARCHAR(32) NOT NULL,
  `title` VARCHAR(150) NOT NULL,
  `severity` VARCHAR(20) NOT NULL,
  `description` TEXT NOT NULL,
  `status` VARCHAR(20) NOT NULL DEFAULT 'NEW',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `resolved_at` DATETIME NULL,
  `resolved_by` INT NULL,
  UNIQUE KEY `uq_alert_event_rule` (`event_id`, `rule_code`),
  INDEX `idx_alerts_rule` (`rule_code`),
  INDEX `idx_alerts_severity` (`severity`),
  INDEX `idx_alerts_status` (`status`),
  CONSTRAINT `fk_alerts_event` FOREIGN KEY (`event_id`)
    REFERENCES `security_events` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_alerts_resolver` FOREIGN KEY (`resolved_by`)
    REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Audit Logs Table
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NULL,
  `action` VARCHAR(64) NOT NULL,
  `details` TEXT NULL,
  `ip_address` VARCHAR(45) NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_audit_action` (`action`),
  INDEX `idx_audit_user` (`user_id`),
  INDEX `idx_audit_created` (`created_at`),
  CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`)
    REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
