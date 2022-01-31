/*
 * Copyright (c) 2018-2019 Janik Kleinhoff
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Services awareness of group registrations
 * Core functionality - Utility functions
 */

#include "lc-compat.h"
#include "main.h"

bool is_valid_project_name(const char * const name)
{
	/* Screen for anything that'd break parameter parsing or the protocol.
	 * Don't check for other kinds of stupidity as this module is meant to
	 * be used by network staff, who should know better. *grumble*
	 * Addendum: also screen for nonprintables to avoid invisible characters
	 * in project names
	 */
	for (const char *c = name; *c; c++)
	{
		if (!isprint(*c) || *c == ' ' || *c == '\n' || *c == '\r')
		{
			return false;
		}
	}
	return !(strlen(name) >= PROJECTNAMELEN);
}

// Remove the last -suffix from a channel name by replacing the separator with a NUL.
// Returns false if there was no -suffix to remove.
static bool trim_last_component(char *chan)
{
	for (size_t i = strlen(chan) - 1; i > 0; i--)
	{
		if (strchr(projectsvs.config.namespace_separators, chan[i]))
		{
			chan[i] = '\0';
			return true;
		}
	}

	return false;
}

// Looks up a project by channel name.
// If out_namespace is a non-NULL pointer to char*, it will be set to point
// at a buffer containing the channel namespace that was matched, and the caller
// will have to free() it later.
//
// If no project is found, NULL is returned and out_namespace is left untouched.
// Callers that wish to free *out_namespace either way may set it to NULL beforehand.
struct projectns *channame_get_project(const char * const name, char **out_namespace)
{
	char *buf = sstrdup(name);

	struct projectns *p = NULL;

	do {
		p = mowgli_patricia_retrieve(projectsvs.projects_by_channelns, buf);
		if (p)
			break;
	} while (trim_last_component(buf));

	if (out_namespace && p)
		*out_namespace = buf;
	else
		free(buf);

	return p;
}

mowgli_list_t *myuser_get_projects(myuser_t *mu)
{
	mowgli_list_t *l;

	l = privatedata_get(mu, MYUSER_PRIVDATA_NAME);
	if (l)
		return l;

	l = mowgli_list_create();
	privatedata_set(mu, MYUSER_PRIVDATA_NAME, l);

	return l;
}

// TODO: move to projectns/mark?
void show_marks(sourceinfo_t *si, struct projectns *p)
{
	mowgli_node_t *n;
	MOWGLI_ITER_FOREACH(n, p->marks.head)
	{
		struct project_mark *m = n->data;

		struct tm tm;
		char time[BUFSIZE];
		tm = *localtime(&m->time);

		strftime(time, sizeof time, TIME_FORMAT, &tm);

		myuser_t *setter;
		const char *setter_name;

		if ((setter = myuser_find_uid(m->setter_id)) != NULL)
			setter_name = entity(setter)->name;
		else
			setter_name = m->setter_name;

		if (irccasecmp(setter_name, m->setter_name))
		{
			command_success_nodata(
					si,
					_("Mark \2%d\2 set by \2%s\2 (%s) on \2%s\2: %s"),
					m->number,
					m->setter_name,
					setter_name,
					time,
					m->mark
					);
		}
		else
		{
			command_success_nodata(
					si,
					_("Mark \2%d\2 set by \2%s\2 on \2%s\2: %s"),
					m->number,
					setter_name,
					time,
					m->mark
					);
		}
	}
}
