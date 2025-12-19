import { IoChatbubbleEllipsesOutline } from "react-icons/io5";
import { IoPersonOutline } from "react-icons/io5";
import { TbAlertSquare } from "react-icons/tb";
import { IoAlertCircleOutline } from "react-icons/io5";
import { TbCalendarClock } from "react-icons/tb";
import { FaUsers } from "react-icons/fa";
import { GrUserAdmin } from "react-icons/gr";
import { PiCookieLight } from "react-icons/pi";
// Create a function to return the JSX
const getImage = (icon) => {
    return icon();
};

export const links = [
    {
        title: "Message Board",
        to: "/",
        img: getImage(IoChatbubbleEllipsesOutline),
    },
    {
        title: "Profile",
        to: "/profile",
        img: getImage(IoPersonOutline),
    },
    {
        title: "Terms of Services",
        to: "/term",
        img: getImage(TbAlertSquare),
    },
    {
        title: "Privacy Policy",
        to: "/privacy",
        img: getImage(IoAlertCircleOutline),
    },
    {
        title: "Cookie Policy",
        to: "/cookie",
        img: getImage(PiCookieLight),
    }
];

export const admin_links = [
    {
        title: "Message Board",
        to: "/",
        img: getImage(IoChatbubbleEllipsesOutline),
    },
    {
        title: "Scheduling Messages",
        to: "/schedule",
        img: getImage(TbCalendarClock),
    },
    {
        title: "Push Notifications",
        to: "/notification",
        img: getImage(TbAlertSquare),
    },
    {
        title: "Employee Directory",
        to: "/employee",
        img: getImage(FaUsers),
    },
    {
        title: "Add Admin",
        to: "/admin",
        img: getImage(GrUserAdmin),
    }
];