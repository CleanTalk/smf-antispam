<?php

/**
 * This is project's console commands configuration for Robo task runner.
 *
 * @see http://robo.li/
 */
class RoboFile extends \Robo\Tasks
{
    const PACKAGE = 'antispam_cleantalk_smf';
    const VERSION = '1.94';

    const SMF_VERSION = '2.0.11'; // for forumPrepare

    /**
     * Build SMF zip-package
     */
    public function build()
    {
        $this->taskFileSystemStack()
            ->mkdir($this->getBuildDir())
            ->run();

        $this->taskCleanDir($this->getBuildDir())
            ->run();

        $this->createModArchive();
    }

    /**
     * Prepare clean SMF forum
     */
    public function forumPrepare()
    {
        $version = $this->askDefault("SMF Core Version", self::SMF_VERSION);

        // download
        $zipFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'smf-' . $version . '.zip';
        if (!file_exists($zipFile)) {
            $url = 'http://download.simplemachines.org/index.php/smf_' . str_replace('.', '-', $version) . '_install.zip';
            file_put_contents($zipFile, fopen($url, 'r'));
        }
        // clean dir
        $dir = $this->askDefault("Install directory path", '/var/www/html/smf');
        if (is_dir($dir)) {
            $clean = $this->askDefault('Directory exists. Clean ' . $dir, 'y');
            if ($clean == 'y') {
                $this->taskCleanDir([$dir])->run();
            }
        }
        // extract
        $zip = new ZipArchive;
        if ($zip->open($zipFile) === true) {
            $zip->extractTo($dir);
            $zip->close();
            $this->say('Extracted ' . $zipFile);
        }

        // fix file and folder access
        $this->taskExecStack()
            ->stopOnFail()
            ->exec('chown www-data:www-data -R ' . $dir)
            ->exec('chmod og+rwx -R ' . $dir)
            ->run();

        //database
        $dbName = $this->askDefault("MySQL DB_NAME", 'smf');
        $rootPassword = $this->askDefault("MySQL root password", '');

        $dbh = new PDO('mysql:host=localhost', 'root', $rootPassword);
        $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $dbh->query("DROP DATABASE IF EXISTS $dbName");
        $dbh->query("CREATE DATABASE $dbName");
        $this->say('Created schema ' . $dbName);
    }

    public function versionInc()
    {
        //@todo
    }

    /**
     * Version checks
     */
    public function versionCheck()
    {
        do {
            $version = $this->ask('Check for version, example 1.51');
            $version = trim($version);
        } while (empty($version));
        $errors = [];
        if (!preg_match('#\<version\>' . preg_quote($version) . '\<\/version\>#m', file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . 'package-info.xml'))) {
            $errors[] = 'Not found tag <version> in package-info.xml';
        }
        if (!preg_match('#Version: ' . preg_quote($version) . "\n#m", file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . 'readme.txt'))) {
            $errors[] = 'Not found version in readme.txt';
        }
        if (!preg_match('#Version ' . preg_quote($version) . " #m", file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . 'CHANGELOG'))) {
            $errors[] = 'Not found version in CHANGELOG';
        }
        $ctVersion = str_replace('.', '', $version);
        if (!preg_match("#'smf-" . preg_quote($ctVersion) . "'\);#m", file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . 'CleantalkMod.php'))) {
            $errors[] = 'Not found CT_AGENT_VERSION in CleantalkMod.php';
        }
        if (count($errors)) {
            $this->say("***ERRORS***\n" . implode("\n", $errors));
        } else {
            $this->say("All OK");
        }
    }

    private function createModArchive()
    {
        $zip = new ZipArchive();
        $filename = self::PACKAGE . '-' . self::VERSION . '.zip';
        if ($zip->open($this->getBuildDir() . DIRECTORY_SEPARATOR . $filename, ZipArchive::CREATE) !== true) {
            throw new RuntimeException('Zip create error');
        }
        $zip->addGlob('*.php');
        $zip->addGlob('*.xml');
        $zip->addGlob('*.txt');
        $zip->addGlob('languages/*.xml');
        $zip->addGlob('upgrades/*.*');
        $zip->deleteName('RoboFile.php'); //self
        $zip->close();
        $this->say("Created zip $filename");
    }

    private function getBuildDir()
    {
        return __DIR__ . DIRECTORY_SEPARATOR . 'build';
    }
}
