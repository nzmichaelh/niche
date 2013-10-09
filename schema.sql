-- MySQL dump 10.9
--
-- Host: localhost    Database: mofi
-- ------------------------------------------------------
-- Server version	4.1.15-Debian_1ubuntu5

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `1_accesslog`
--

DROP TABLE IF EXISTS `1_accesslog`;
CREATE TABLE `1_accesslog` (
  `title` varchar(255) default NULL,
  `path` varchar(255) default NULL,
  `url` varchar(255) default NULL,
  `hostname` varchar(128) default NULL,
  `uid` int(10) unsigned default '0',
  `timestamp` int(11) unsigned NOT NULL default '0',
  `run_time` float default NULL,
  KEY `accesslog_timestamp` (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `1_accesslog`
--


/*!40000 ALTER TABLE `1_accesslog` DISABLE KEYS */;
LOCK TABLES `1_accesslog` WRITE;
UNLOCK TABLES;
/*!40000 ALTER TABLE `1_accesslog` ENABLE KEYS */;

--
-- Table structure for table `1_comments`
--

DROP TABLE IF EXISTS `1_comments`;
CREATE TABLE `1_comments` (
  `commentID` int(10) unsigned NOT NULL auto_increment,
  `linkID` int(10) unsigned NOT NULL default '0',
  `userID` int(10) unsigned NOT NULL default '0',
  `philterID` int(3) unsigned NOT NULL default '1',
  `content` text NOT NULL,
  `timestamp` int(14) NOT NULL default '0',
  PRIMARY KEY  (`commentID`),
  KEY `linkID` (`linkID`),
  KEY `userID` (`userID`),
  KEY `timestamp` (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `1_comments`
--


/*!40000 ALTER TABLE `1_comments` DISABLE KEYS */;
LOCK TABLES `1_comments` WRITE;
UNLOCK TABLES;
/*!40000 ALTER TABLE `1_comments` ENABLE KEYS */;

--
-- Table structure for table `1_links`
--

DROP TABLE IF EXISTS `1_links`;
CREATE TABLE `1_links` (
  `linkID` int(10) unsigned NOT NULL auto_increment,
  `userID` int(10) unsigned NOT NULL default '0',
  `philterID` int(3) unsigned NOT NULL default '1',
  `category` int(4) unsigned NOT NULL default '0',
  `timestamp` int(14) unsigned NOT NULL default '0',
  `title` tinytext NOT NULL,
  `URL` tinytext NOT NULL,
  `URL_description` mediumtext NOT NULL,
  `description` mediumtext NOT NULL,
  `extended` mediumtext NOT NULL,
  `closed` int(2) default '0',
  `hidden` int(2) default '0',
  PRIMARY KEY  (`linkID`),
  KEY `category` (`category`),
  KEY `userID` (`userID`),
  KEY `timestamp` (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `1_links`
--


/*!40000 ALTER TABLE `1_links` DISABLE KEYS */;
LOCK TABLES `1_links` WRITE;
UNLOCK TABLES;
/*!40000 ALTER TABLE `1_links` ENABLE KEYS */;

--
-- Table structure for table `1_pings`
--

DROP TABLE IF EXISTS `1_pings`;
CREATE TABLE `1_pings` (
  `linkID` int(10) NOT NULL default '0',
  `URL` tinytext NOT NULL,
  `title` text NOT NULL,
  `excerpt` text NOT NULL,
  `blog_name` tinytext NOT NULL,
  `timestamp` int(14) NOT NULL default '0',
  PRIMARY KEY  (`linkID`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `1_pings`
--


/*!40000 ALTER TABLE `1_pings` DISABLE KEYS */;
LOCK TABLES `1_pings` WRITE;
UNLOCK TABLES;
/*!40000 ALTER TABLE `1_pings` ENABLE KEYS */;

--
-- Table structure for table `1_users`
--

DROP TABLE IF EXISTS `1_users`;
CREATE TABLE `1_users` (
  `userID` int(10) unsigned NOT NULL auto_increment,
  `user_group` int(4) unsigned NOT NULL default '1',
  `username` tinytext NOT NULL,
  `password` tinytext NOT NULL,
  `added` int(14) unsigned NOT NULL default '0',
  `email` tinytext NOT NULL,
  `realname` tinytext NOT NULL,
  `aim` varchar(30) NOT NULL default '',
  `homepage` tinytext NOT NULL,
  `bio` mediumtext NOT NULL,
  `preferences` text,
  `last_visit` int(14) unsigned NOT NULL default '0',
  `contacts` text,
  PRIMARY KEY  (`userID`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Dumping data for table `1_users`
--


/*!40000 ALTER TABLE `1_users` DISABLE KEYS */;
LOCK TABLES `1_users` WRITE;
UNLOCK TABLES;
/*!40000 ALTER TABLE `1_users` ENABLE KEYS */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

CREATE TABLE `1_likes` (
  `likeID` int(10) unsigned NOT NULL auto_increment,
  `commentID` int(10) unsigned NOT NULL,
  `userID` int(10) unsigned NOT NULL default '0',
  KEY `likeID` (`likeID`),
  KEY `commentID` (`commentID`),
  KEY `userID` (`userID`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
