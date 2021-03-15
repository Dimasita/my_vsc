SET NAMES utf8;
SET time_zone = '+03:00';


DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
    `id` integer unsigned NOT NULL AUTO_INCREMENT,
    `git_id` varchar(20) NOT NULL,
    `github_token` VARCHAR(255) NOT NULL,
    `refresh_token` varchar(255) NOT NULL,
    `refresh_token_expire` timestamp NOT NULL,
    PRIMARY KEY (`id`)
)   ENGINE=InnoDB DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `projects`;
CREATE TABLE `projects` (
    `id` integer unsigned NOT NULL AUTO_INCREMENT,
    `uid` integer unsigned NOT NULL,
    `name` varchar(60) not null,
    `port` integer unsigned NOT NULL,
    PRIMARY KEY (`id`),
    foreign key (`uid`)
        references `users` (`id`)
)   ENGINE=InnoDB DEFAULT CHARSET=utf8;