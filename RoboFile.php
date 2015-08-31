<?php

/**
 * This is project's console commands configuration for Robo task runner.
 *
 * @see http://robo.li/
 */
class RoboFile extends \Robo\Tasks
{
    const PACKAGE = 'antispam_cleantalk_smf';
    const VERSION = '1.51';

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