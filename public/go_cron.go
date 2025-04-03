package public

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"time"

	"github.com/go-co-op/gocron"
)

var (
	s *gocron.Scheduler
)

func init() {
	InitScheduler()
}

func InitScheduler() {
	if s == nil {
		s = gocron.NewScheduler(time.Local)
		s.TagsUnique()
	}
}

func AddTaskOnce(handler func(), delay time.Duration) (err error) {
	if handler == nil {
		return err
	}
	if delay == 0 {
		core.RecoveryGo(handler).Run(nil)
		return err
	}

	core.RecoveryGo(func() {
		time.Sleep(delay)
		handler()
	}).Run(nil)

	return err
}

func AddTaskInterval(name string, interval time.Duration, task func(), delay time.Duration) (job *gocron.Job, err error) {
	if delay == 0 {
		job, err = s.Every(interval).Tag(name).Do(core.WrapHandler(task))
	} else {
		err = AddTaskOnce(func() {
			logging.Debug("Add Task ", name)
			_, err = s.Every(interval).Tag(name).Do(core.WrapHandler(task))
			if err != nil {
				logging.Error("Failed to add task: ", "任务->", name, err, interval, delay)
			}
		}, delay)
	}

	if err != nil {
		logging.Error("Failed to add task2: ", "任务->", name, err)
		return nil, err
	}

	return job, err
}

func AddTaskDayAtTime(name string, datetime string, task func(), delay time.Duration) (job *gocron.Job, err error) {
	if delay == 0 {
		job, err = s.Every(1).Tag(name).Day().At(datetime).Do(core.WrapHandler(task))
	} else {
		err = AddTaskOnce(func() {
			_, err = s.Every(1).Tag(name).Day().At(datetime).Do(core.WrapHandler(task))
			if err != nil {
				logging.Error("Failed to add task: ", "任务->", name, err)
			}
		}, delay)
	}

	if err != nil {
		logging.Error("Failed to add task2: ", "任务->", name, err)
		return nil, err
	}

	return job, err
}

func AddTaskDay(name string, day int, task func(), delay time.Duration) (job *gocron.Job, err error) {
	if delay == 0 {
		job, err = s.Every(day).Tag(name).Days().Do(core.WrapHandler(task))
	} else {
		err = AddTaskOnce(func() {
			_, err = s.Every(day).Tag(name).Days().Do(core.WrapHandler(task))
			if err != nil {
				logging.Error("Failed to add task: ", "任务->", name, err)
			}
		}, delay)
	}

	if err != nil {
		logging.Error("Failed to add task2: ", "任务->", name, err)
		return nil, err
	}

	return job, err
}

func AddTaskCron(name string, cron string, task func()) (job *gocron.Job, err error) {
	job, err = s.CronWithSeconds(cron).Tag(name).Do(core.WrapHandler(task))

	if err != nil {
		logging.Error("Failed to add task: ", "任务->", name, err)
		return nil, err
	}

	return job, err
}

func AddTaskWeekday(name string, weekday time.Weekday, task func()) (job *gocron.Job, err error) {
	job, err = s.Every(1).Tag(name).Week().Weekday(weekday).Do(core.WrapHandler(task))
	if err != nil {
		logging.Error("Failed to add task: ", "任务->", name, err)
		return nil, err
	}
	return job, err
}

func StartSchedulerAsync() {
	s.StartAsync()
}

func StartSchedulerBlocking() {
	s.StartBlocking()
}

func ClearScheduler(s *gocron.Scheduler) {
	s.Clear()
}

func StopScheduler() {
	s.Stop()
}

func RemoveTask(job *gocron.Job) {
	s.RemoveByReference(job)
}

func NextRun(job *gocron.Job) time.Time {
	t := job.NextRun()
	return t
}

func RemoveTaskByTag(name string) bool {
	err := s.RemoveByTag(name)
	if err != nil {
		return false
	}
	return true
}

func GetTaskByTag(name string) []*gocron.Job {
	job, err := s.FindJobsByTag(name)
	if err != nil {
		return nil
	}
	return job
}

func RunTaskByTag(name string) {
	_ = s.RunByTag(name)

}

func GetAllTask() []string {
	tasks := s.GetAllTags()
	return tasks
}

func CheckTaskByTag(name string) bool {
	tasks := GetAllTask()
	for _, v := range tasks {
		if v == name {
			return true
		}
	}
	return false
}
