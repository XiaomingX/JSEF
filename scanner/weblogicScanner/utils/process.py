import os
import random
import threading
import time
from multiprocessing import Manager, Process, Queue
from multiprocessing.managers import SyncManager
from typing import Any, Callable, Dict, List, Union

SIG_ACTI = 40
SIG_SLEP = 30
SIG_LINE = 0
SIG_FINI = -10
SIG_STOP = -20
SIG_TMNT = -30

KEY_STATUS = 'CURRENT_STATUS'


class AutoProcess:
    auto_end: Union[bool, int]
    auto_end_wait_time: int
    auto_end_last_time: int
    tasks_waiting: List[Process]
    tasks_running: List[Process]
    tasks_finish_number: int
    signal: int
    number: int
    __thread_active_tasks_waiting: threading.Thread
    __thread_clear_tasks_complate: threading.Thread
    activated_or_not: bool
    scan_interval: float
    __queue: SyncManager.Queue
    TASK_KEY: str

    def __init__(self,
                 number: int = 8,
                 auto_end: Union[bool, int] = 3,
                 scan_interval: float = 1,
                 queue: SyncManager.Queue = None) -> None:
        '''
        同步函数，等待任务执行结束退出
        number: 最大运行进程数量，该值小于0时，只要任务等待区有任务就会无限塞入任务运行区运行
        auto_end: 任务运行完后是否自动结束
        scan_interval: 扫描间隔，不建议低于1，否则线程太过占用系统资源，根据运行设备情况自定义
        '''
        self.auto_end = auto_end
        self.auto_end_last_time = time.time()
        if isinstance(auto_end, int):
            self.auto_end_wait_time = auto_end
        else:
            self.auto_end_wait_time = 30
        self.tasks_waiting = []
        self.tasks_running = []
        self.signal = SIG_SLEP
        self.number = number
        self.is_activated = False
        self.scan_interval = scan_interval
        self.tasks_finish_number = 0
        if queue:
            self.__queue = queue
        else:
            manager = Manager()
            self.__queue = manager.Queue()
        self.TASK_KEY = 'TASKID'
        self.RET_KEY = 'RETURNDATA'

    def __active_tasks_waiting(self):
        '''
        将任务等待区中的任务放入多线程运行，定期扫描等待区任务
        scan_interval: 扫描间隔
        '''
        while True:
            if self.signal < SIG_LINE:
                return
            if self.auto_end and time.time() - (
                    self.auto_end_last_time +
                    self.auto_end_wait_time) > 0 and len(
                        self.tasks_waiting) == 0 and len(
                            self.tasks_running) == 0 and self.is_activated:
                self.signal = SIG_FINI
                return
            for i in range(len(self.tasks_waiting)):
                if self.number > 0 and len(self.tasks_running) >= self.number:
                    break
                process = self.tasks_waiting.pop(0)
                process.start()
                self.tasks_running.append(process)
                self.is_activated = True
                self.signal = SIG_ACTI
            if len(self.tasks_waiting) == 0 and len(self.tasks_running) == 0:
                self.signal = SIG_SLEP
            time.sleep(self.scan_interval)

    def __clear_tasks_complate(self):
        '''
        将任务运行区已完成的任务定期进行清理，定期扫描运行区任务
        scan_interval: 扫描间隔
        '''
        while True:
            for process in self.tasks_running:
                if self.signal == SIG_TMNT:
                    process.kill()
                    process.join()
                    process.close()
                elif not process.is_alive():
                    self.tasks_running.remove(process)
                    if hasattr(process, 'close'):
                        process.close()
                    self.auto_end_last_time = time.time()
                    self.tasks_finish_number += 1
            if self.signal == SIG_TMNT:
                return
            if self.signal < SIG_LINE and len(self.tasks_running) == 0:
                return
            time.sleep(self.scan_interval)

    def get_return(self, queue: SyncManager.Queue = None):
        '''
        '''
        if queue:
            while not queue.empty():
                yield queue.get()
        while not self.__queue.empty():
            yield self.__queue.get()

    def gen_task_id(self) -> str:
        return os.urandom(16).hex()

    def put_task(self,
                 func: Callable,
                 args: List = None,
                 kwargs: Dict = None,
                 queue: Union[bool, SyncManager.Queue] = False) -> str:
        '''
        提交待执行的任务，返回任务id
        func: 要多进程运行的函数
        args: 任务函数的参数
        kwargs: 任务函数的kw参数
        '''
        if not args:
            args = []
        if not kwargs:
            kwargs = {}
        if queue and isinstance(queue, bool):
            args.insert(0, self.__queue)
        else:
            args.insert(0, queue)
        self.tasks_waiting.append(
            Process(target=func, args=args, kwargs=kwargs))

    def wait(self, timeout: Union[int, None] = None):
        '''
        同步函数，等待任务执行结束退出
        timeout: 超时结束
        '''
        self.__thread_active_tasks_waiting.join(timeout)
        self.__thread_clear_tasks_complate.join(timeout)

    def stop(self):
        '''
        向引擎发出停止信号
        '''
        self.signal = SIG_STOP

    def terminate(self):
        '''
        向引擎发出终止信号
        '''
        self.signal = SIG_TMNT

    def run(self):
        '''
        该函数会将输入的函数放入线程池中进行调度，调度会把任务放入子进程中进行运行
        scan_interval: 扫描间隔
        '''
        self.__thread_active_tasks_waiting = threading.Thread(
            target=self.__active_tasks_waiting)
        self.__thread_clear_tasks_complate = threading.Thread(
            target=self.__clear_tasks_complate)
        self.__thread_active_tasks_waiting.start()
        self.__thread_clear_tasks_complate.start()


