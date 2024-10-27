


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
SET NAMES utf8mb4;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


# Dump of table commands
# ------------------------------------------------------------

DROP TABLE IF EXISTS `commands`;

CREATE TABLE `commands` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_type` varchar(50) NOT NULL,
  `command` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb3;

LOCK TABLES `commands` WRITE;
/*!40000 ALTER TABLE `commands` DISABLE KEYS */;

INSERT INTO `commands` (`id`, `device_type`, `command`) VALUES
	(1, 'juniper_junos', 'show configuration | no-more'),
	(2, 'hp_comware', 'display current-configuration'),
	(3, 'cisco_ios', 'show running-config');

/*!40000 ALTER TABLE `commands` ENABLE KEYS */;
UNLOCK TABLES;



# Dump of table perangkat
# ------------------------------------------------------------

DROP TABLE IF EXISTS `perangkat`;

CREATE TABLE `perangkat` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip` varchar(50) DEFAULT NULL,
  `location` varchar(50) DEFAULT NULL,
  `hostname` varchar(255) DEFAULT NULL,
  `username` varchar(50) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `device_type` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=564 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

LOCK TABLES `perangkat` WRITE;
/*!40000 ALTER TABLE `perangkat` DISABLE KEYS */;

INSERT INTO `perangkat` (`id`, `ip`, `location`, `hostname`, `username`, `password`, `device_type`) VALUES
	(561, '192.168.1.1', 'U1', 'SWITCH1', 'admin', 'admin', 'juniper_junos'),
	(562, '192.168.1.2', 'U1', 'SWITCH2', 'admin', 'admin', 'hp_comware'),
	(563, '192.168.1.3', 'U1', 'SWITCH3', 'admin', 'admin', 'cisco_ios');

/*!40000 ALTER TABLE `perangkat` ENABLE KEYS */;
UNLOCK TABLES;



# Dump of table settings
# ------------------------------------------------------------

DROP TABLE IF EXISTS `settings`;

CREATE TABLE `settings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `next_backup_time` datetime DEFAULT NULL,
  `backup_frequency` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3;

LOCK TABLES `settings` WRITE;
/*!40000 ALTER TABLE `settings` DISABLE KEYS */;

INSERT INTO `settings` (`id`, `next_backup_time`, `backup_frequency`) VALUES
	(1, '2024-10-13 00:01:00', 'weekly');

/*!40000 ALTER TABLE `settings` ENABLE KEYS */;
UNLOCK TABLES;



# Dump of table users
# ------------------------------------------------------------

DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;

INSERT INTO `users` (`id`, `username`, `password`) VALUES
	(2, 'admin', '$2b$12$qb3UJDlo3CXlOYabnNB.eukc1Y69o.vMdmFg3ZX4NsLqpwbMmXFbu');

/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;



/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;


