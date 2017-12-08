package com.github.fitosoft.openkloudkrypt.filewatcher

import java.nio.file.StandardWatchEventKinds._
import java.nio.file.{FileSystems, Path, WatchService}

import scala.collection.JavaConverters._
import scala.util.{Failure, Success, Try}

/**
  * Watches for changes of files in a specified folder and sub folders.
  */
class FileWatcher(pathToWatch: Path) extends Runnable {
  val watcher: WatchService = FileSystems.getDefault.newWatchService()

  pathToWatch.register(watcher, ENTRY_CREATE, ENTRY_MODIFY, ENTRY_DELETE)

  override def run(): Unit = {
    while (true) {
      Try {
        val key = watcher.take()

        for (event <- asScalaIterator(key.pollEvents().iterator())) {
          val name = event.context().asInstanceOf[Path]
          val pathToFile = pathToWatch.resolve(name)
          val pType = if (pathToFile.toFile.isDirectory) "dir" else "file"
          println(s"${event.kind()} -> $pathToFile ($pType)")

          key.reset()
        }
      } match {
        case Success(_) => ()
        case Failure(e) => println("Error: " + e) // TODO Log error...
      }
    }

  }
}
